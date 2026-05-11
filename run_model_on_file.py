from transformers import T5Tokenizer, T5ForConditionalGeneration
import json

# Load model
model_path = "./t5-log-parser"

tokenizer = T5Tokenizer.from_pretrained(model_path)
model = T5ForConditionalGeneration.from_pretrained(model_path)


# Convert KV output → JSON
def kv_to_json(text):
    result = {}

    
    keys = ["timestamp", "log_type", "source_ip", "user", "message"]

    for key in keys:
        text = text.replace(f" {key}:", f"\n{key}:")

    for line in text.split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            result[k.strip()] = v.strip()

    return result


# Parse one log
def parse_log(log_line):
    input_text = f"parse log: {log_line}"

    inputs = tokenizer(
        input_text,
        return_tensors="pt",
        truncation=True,
        max_length=64
    )

    outputs = model.generate(
        **inputs,
        max_length=64,
        num_beams=6,
        no_repeat_ngram_size=2,
        early_stopping=True,
        repetition_penalty=1.2
    )

    decoded = tokenizer.decode(outputs[0], skip_special_tokens=True)

    return kv_to_json(decoded)


# Process entire file
def process_file(input_file, output_file):
    results = []

    with open(input_file, "r") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue

            parsed = parse_log(line)

            # Optional: keep raw log too
            parsed["raw"] = line

            results.append(parsed)

            # Progress (useful for large files)
            if i % 100 == 0:
                print(f"Processed {i} logs")

    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nDone. Output saved to {output_file}")




process_file("ssh_logs.txt", "parsed_logs_output.json")



'''
custom regex extractor.
'''