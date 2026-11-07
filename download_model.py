"""
Helper script to download the model files cleanly to a local folder (models/).
This avoids hidden cache symlink issues on Windows and makes offline execution 100% self-contained.
"""

import os
import requests
from tqdm import tqdm

MODEL_FILES = [
    "config.json",
    "generation_config.json",
    "tokenizer_config.json",
    "tokenizer.json",
    "vocab.json",
    "merges.txt",
    "model.safetensors"
]

BASE_URL = "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct/resolve/main"
TARGET_DIR = os.path.join(os.path.dirname(__file__), "models", "Qwen2.5-0.5B-Instruct")


def download_model():
    os.makedirs(TARGET_DIR, exist_ok=True)
    print(f"Ensuring local model files in: {TARGET_DIR}")

    for filename in MODEL_FILES:
        target_path = os.path.join(TARGET_DIR, filename)
        if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
            print(f"  [OK] {filename} already exists ({os.path.getsize(target_path)} bytes).")
            continue

        url = f"{BASE_URL}/{filename}"
        print(f"  Downloading {filename}...")
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()

        total_size = int(response.headers.get("content-length", 0))
        temp_path = target_path + ".downloading"

        with open(temp_path, "wb") as f, tqdm(
            desc=filename,
            total=total_size,
            unit="B",
            unit_scale=True,
            unit_divisor=1024,
        ) as bar:
            for chunk in response.iter_content(chunk_size=1024 * 1024):  # 1MB chunks
                if chunk:
                    f.write(chunk)
                    bar.update(len(chunk))

        os.replace(temp_path, target_path)
        print(f"  [DONE] Saved {filename}")

    print("Model is ready for offline local inference!")


if __name__ == "__main__":
    download_model()
