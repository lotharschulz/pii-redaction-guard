title TODO

## steps

```sh
# precondition: uv installed
uv init
uv add presidio-analyzer presidio-anonymizer spacy
uv add https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
# add the code to main.py
# run the code
uv run main.py
```