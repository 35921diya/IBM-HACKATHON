
from risk_engine import analyze_url

examples = [
    "https://example.com",
    "http://192.0.2.1/login",
    "https://bit.ly/example",
    "javascript:alert(1)",
    "not a valid URL"
]

for url in examples:
    print("\nURL:", url)
    print(analyze_url(url))
