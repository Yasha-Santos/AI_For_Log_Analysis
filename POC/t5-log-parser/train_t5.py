from datasets import Dataset
from transformers import T5Tokenizer, T5ForConditionalGeneration, Trainer, TrainingArguments
import json

with open("t5_dataset_final.json") as f:
    data = json.load(f)

dataset = Dataset.from_list(data)

dataset = dataset.select(range(1500))# Use a subset for faster training during development

model_name = "t5-small"
#model_name = "google/flan-t5-small"  # Better performance, but slower training. Use if you have time and resources.

tokenizer = T5Tokenizer.from_pretrained(model_name)
model = T5ForConditionalGeneration.from_pretrained(model_name)


def preprocess(example):
    inputs = tokenizer(
        example["input"],
        truncation=True,
        padding="max_length",
        max_length=128
    )

    outputs = tokenizer(
        example["output"],
        truncation=True,
        padding="max_length",
        max_length=128
    )

    inputs["labels"] = outputs["input_ids"]
    return inputs


tokenized_dataset = dataset.map(preprocess, batched=True)

training_args = TrainingArguments(
    output_dir="./t5-log-parser",
    per_device_train_batch_size=4,
    num_train_epochs=5,
    learning_rate=2e-4,
    logging_steps=10,
    save_steps=500
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset
)

trainer.train()

model.save_pretrained("./t5-log-parser")
tokenizer.save_pretrained("./t5-log-parser")

print("Training complete")
