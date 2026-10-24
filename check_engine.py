
from risk_engine import analyze_url

tests = [
    "https://example.com",
    "http://192.0.2.1/login",
    "https://bit.ly/example",
    "javascript:alert(1)",
    "",
    "https://example.com:99999"
]

for url in tests:
    try:
        result = analyze_url(url)

        assert isinstance(result["score"], int)
        assert 0 <= result["score"] <= 100
        assert result["level"] in [
            "Low", "Medium", "High", "Critical"
        ]
        assert isinstance(result["findings"], list)
        assert isinstance(result["recommendations"], list)

        print("PASS:", repr(url))
        print("Score:", result["score"])
        print("Level:", result["level"])
        print("-" * 35)

    except Exception as error:
        print("FAIL:", repr(url), error)
