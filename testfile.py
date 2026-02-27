import gzip, json
p="./journal-sanitize-test.json.gz"
data=[
  {"date":"2026-02-27","entry":"ok"},
  {"date":"bad-date","entry":"x"},
  {"date":"2026-02-26","entry":123},
  ["not-a-dict"]
]
with gzip.open(p,"wt",encoding="utf-8") as f:
    json.dump(data,f)
print(p)
