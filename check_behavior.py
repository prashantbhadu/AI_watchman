from watchman.middleware.normalizer import normalize
from watchman.middleware.event_builder import build_event
from watchman.middleware.failure_recorder import FailureRecorder
from watchman.models import Event, Source

# 1) Normalizer
assert normalize("%61%73%73%65%72%74 Admin+%2F") == "assert admin/+", normalize("%61%73%73%65%72%74 Admin+%2F")
assert normalize("ADMIN") == "admin"
assert normalize("Admin%2f") == "admin/"
assert normalize(None) is None
assert normalize(123) == 123
print("normalizer OK:", normalize("%61%73%73%65%72%74 Admin+%2F"))

# 2) Event builder
recorder = FailureRecorder()
ev = build_event(recorder=recorder, method="POST", path="/admin/login", query="user=admin&role=ADMIN",
                 headers={"X-Forwarded-For": "1.2.3.4", "Content-Type": "application/json"},
                 body='{"password":"p\x00ss"}',
                 ip_address="1.2.3.4", user_agent="Mozilla/5.0")
assert ev.source == Source.HTTP_REQUEST
assert ev.request_path == "/admin/login"
assert ev.ip_address == "1.2.3.4"
assert ev.evidence["method"] == "post"
assert ev.evidence["path"] == "/admin/login"
assert ev.evidence["query"] == "user=admin&role=admin"
assert ev.evidence["body"] == '{"password":"p\x00ss"}'
print("event builder OK:", ev.event_id)

# 3) Fail-open
recorder2 = FailureRecorder()
ev2 = Event(source=Source.HTTP_REQUEST, request_path="/slow")
record_failure(recorder2, ev2, RuntimeError("engine died"))
assert not recorder2.was_pipeline_ok()
print("fail-open OK: pipeline_ok =", not recorder2.was_pipeline_ok())
print("recorded failures:", len(recorder2.recent()))
print("ALL BEHAVIORAL CHECKS PASSED")
