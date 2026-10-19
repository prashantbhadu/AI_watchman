"""Standalone behavioral verification for AI Watchman middleware."""

import sys


def main():
    sys.path.insert(0, ".")

    from fastapi import FastAPI
    from starlette.middleware.exceptions import ExceptionMiddleware
    from starlette.testclient import TestClient

    from watchman.middleware.event_builder import record_failure
    from watchman.middleware.failure_recorder import FailureRecorder
    from watchman.middleware.normalizer import normalize
    from watchman.models import Event, Source

    from watchman.middleware.fastapi_middleware import WatchmanMiddleware

    passed = 0
    failed = 0

    def check(condition, message):
        nonlocal passed, failed
        if condition:
            passed += 1
            print("PASS:", message)
        else:
            failed += 1
            print("FAIL:", message)

    # 1) Normalizer: URL-decode and lowercase
    encoded = "%61%73%73%65%72%74 Admin+%2F"
    expected_normalize = "assert admin+/"
    result = normalize(encoded)
    check(result == expected_normalize, "normalize('%s') == %r" % (encoded, expected_normalize))
    check(normalize("ADMIN") == "admin", "normalize('ADMIN') == 'admin'")
    check(normalize(None) is None, "normalize(None) is None")
    check(normalize(123) == 123, "normalize(123) == 123")

    # 2) Event builder
    app = FastAPI()
    recorder = FailureRecorder()
    app.add_middleware(WatchmanMiddleware, failure_recorder=recorder)

    @app.get("/hello")
    def hello():
        return {"msg": "hi"}

    client = TestClient(app)
    r = client.get("/hello?name=Admin%20%2B%20%2520%20")
    check(r.status_code == 200, "GET /hello returns 200")
    check(r.json() == {"msg": "hi"}, "GET /hello returns {'msg': 'hi'}")

    # 3) Fail-open
    app2 = FastAPI()
    recorder2 = FailureRecorder()
    app2.add_middleware(WatchmanMiddleware, failure_recorder=recorder2)
    app2.add_middleware(ExceptionMiddleware)

    @app2.get("/boom")
    def boom():
        raise RuntimeError("route crashed")

    client2 = TestClient(app2)
    try:
        client2.get("/boom")
    except Exception:
        pass

    check(len(recorder2._failures) == 1, "failure recorded")
    if recorder2._failures:
        f = recorder2._failures[0]
        check(f.event is not None, "failure has event")
        check(f.exception is not None, "failure has exception")
        check(f.event.request_path == "/boom", "event request_path is /boom")
        check(not recorder2.was_pipeline_ok(), "pipeline marked as not OK")

    check(len(recorder2.recent()) == 1, "recent() returns 1 failure")
    check(bool(recorder2) == True, "bool(recorder) is True")

    print()
    print("RESULTS: %d passed, %d failed" % (passed, failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
