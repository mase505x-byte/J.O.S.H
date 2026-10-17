#!/usr/bin/env bash
# Train a small defensive classifier from a labeled CSV.
# CSV format: numeric feature columns followed by a binary label column (0 or 1).
# This template analyzes supplied data only; it does not scan or contact websites.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 training-data.csv" >&2
  exit 2
fi

command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
python3 - "$1" <<'PY'
import csv
import math
import random
import sys

try:
	with open(sys.argv[1], newline="", encoding="utf-8") as source:
		rows = list(csv.reader(source))
	if len(rows) < 3:
		raise ValueError("CSV needs a header and at least two labeled examples")
	header, data = rows[0], rows[1:]
	if len(header) < 2:
		raise ValueError("Include at least one feature column and a final label column")

	features, labels = [], []
	for line, row in enumerate(data, start=2):
		if len(row) != len(header):
			raise ValueError(f"row {line}: expected {len(header)} columns")
		features.append([float(value) for value in row[:-1]])
		label = int(row[-1])
		if label not in (0, 1):
			raise ValueError(f"row {line}: label must be 0 or 1")
		labels.append(label)

	# Standardize features, then train a one-hidden-layer neural network.
	means = [sum(row[j] for row in features) / len(features) for j in range(len(header) - 1)]
	scales = []
	for j, mean in enumerate(means):
		variance = sum((row[j] - mean) ** 2 for row in features) / len(features)
		scales.append(math.sqrt(variance) or 1.0)
	x = [[(value - means[j]) / scales[j] for j, value in enumerate(row)] for row in features]

	random.seed(7)
	n_in, n_hidden = len(header) - 1, max(4, min(16, len(header) * 2))
	w1 = [[random.uniform(-0.2, 0.2) for _ in range(n_hidden)] for _ in range(n_in)]
	b1 = [0.0] * n_hidden
	w2 = [random.uniform(-0.2, 0.2) for _ in range(n_hidden)]
	b2 = 0.0
	sigmoid = lambda z: 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
	rate = 0.05

	for _ in range(500):
		for row, target in zip(x, labels):
			hidden = [sigmoid(sum(row[i] * w1[i][h] for i in range(n_in)) + b1[h]) for h in range(n_hidden)]
			output = sigmoid(sum(hidden[h] * w2[h] for h in range(n_hidden)) + b2)
			error = output - target
			grad2 = error * output * (1.0 - output)
			old_w2 = w2[:]
			for h in range(n_hidden):
				grad1 = grad2 * old_w2[h] * hidden[h] * (1.0 - hidden[h])
				w2[h] -= rate * grad2 * hidden[h]
				b1[h] -= rate * grad1
				for i in range(n_in):
					w1[i][h] -= rate * grad1 * row[i]
			b2 -= rate * grad2

	print("row\tpredicted_label\tconfidence")
	for index, row in enumerate(x, start=1):
		hidden = [sigmoid(sum(row[i] * w1[i][h] for i in range(n_in)) + b1[h]) for h in range(n_hidden)]
		probability = sigmoid(sum(hidden[h] * w2[h] for h in range(n_hidden)) + b2)
		print(f"{index}\t{int(probability >= 0.5)}\t{probability:.4f}")
	print("Note: predictions are a training-template demonstration, not verified security findings.", file=sys.stderr)
except (OSError, ValueError, csv.Error) as error:
	print(f"Error: {error}", file=sys.stderr)
	sys.exit(1)
PY
