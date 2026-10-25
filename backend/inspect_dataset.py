
from pathlib import Path

import pandas as pd
from datasets import load_dataset


DATASET_NAME = "puyang2025/seven-phishing-email-datasets"

TRAIN_SAMPLES = 20000
TEST_SAMPLES = 5000

OUTPUT_DIR = Path(__file__).parent / "data"


def prepare_split(dataset, sample_size, split_name):
    if sample_size > len(dataset):
        raise ValueError(
            f"Requested {sample_size} rows, "
            f"but only {len(dataset)} are available."
        )

    sampled = dataset.shuffle(seed=42).select(range(sample_size))

    rows = []

    for example in sampled:
        subject = str(example.get("subject") or "").strip()
        body = str(example.get("text") or "").strip()

        text = f"Subject: {subject}\n{body}".strip()

        if not text or not text.replace("Subject:", "").strip():
            continue

        rows.append({
            "text": text,
            "label": int(example["label"]),
            "dataset_name": example["dataset_name"],
        })

    dataframe = pd.DataFrame(rows)

    output_path = OUTPUT_DIR / f"email_{split_name}.csv"
    dataframe.to_csv(output_path, index=False, encoding="utf-8")

    print(f"\n{split_name.upper()} DATA")
    print("Saved rows:", len(dataframe))
    print("Label counts:")
    print(dataframe["label"].value_counts().sort_index())
    print("Sources:")
    print(dataframe["dataset_name"].value_counts())
    print("Saved to:", output_path)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Loading the phishing/spam email dataset...")
    dataset = load_dataset(DATASET_NAME)

    print("\nPreparing training examples...")
    prepare_split(dataset["train"], TRAIN_SAMPLES, "train")

    print("\nPreparing held-out test examples...")
    prepare_split(dataset["test"], TEST_SAMPLES, "test")

    print("\nDataset preparation complete.")


if __name__ == "__main__":
    main()
