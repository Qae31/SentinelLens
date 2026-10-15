# SentinelLens — план MVP

Цель: за один день получить законченный конвейер
`auth.log → events → findings (JSON + evidence IDs) → optional triage`, доступный через FastAPI `/docs`.

## Шаги

Каждый шаг: сначала тест, потом код, потом прогон связанных тестов.

0. **Каркас** — `pyproject.toml` (fastapi, pydantic, anthropic, uvicorn, python-multipart; dev: pytest, httpx),
   пакет `sentinellens/`, `tests/`. *Установка зависимостей — после подтверждения.*
1. **Модели** (`models.py`) — `AuthEvent`, `Finding`, `TriageResult`, `AnalysisReport`.
2. **Фикстура** — `tests/fixtures/auth_sample.log`: синтетика с брутфорсом, успешным входом после неудач,
   «почти брутфорсом» (4 попытки / 6 попыток за >5 мин), мусорными строками и строкой с prompt injection.
3. **Парсер** (`parser.py`) + `test_parser.py` — failed/accepted, `invalid user`, ID от номера строки,
   подсчёт пропущенных строк.
4. **Brute force** + тесты — порог 5, окно 5 мин включительно, группировка по `host + src_ip`,
   границы (4 → нет, 5 → да, 5 за 5:01 → нет), один finding на серию.
5. **Success after failures** + тесты — ≥3 failed с тем же `host + IP + username` строго раньше accepted,
   ≤10 мин; отрицательные кейсы: 2 неудачи, другой user/host/IP, accepted до failed, разрыв >10 мин.
6. **Triage** (`triage.py`) + тесты с фейковым клиентом — `none` / `mock` (маркирован) / `claude`;
   Pydantic-валидация ответа, проверка event IDs, обработка невалидного JSON и отсутствия ключа.
7. **API** (`api.py`) + `test_api.py` через `TestClient` — `POST /analyze`, `GET /health`, лимит размера файла.
8. **README** — запуск, пример запроса/ответа, ограничения.
9. *(Опционально, после подтверждения)* — один ручной прогон `triage=claude` с реальным ключом.

## Принятые решения (можно поменять)

- Серия брутфорса: один finding на непрерывную серию, evidence — все failed этой серии.
- `success_after_failures`: нужно ≥3 failed в окне (порог вынесен в константу).
- Severity: brute_force — `medium`, success_after_failures — `high`.
- Год для syslog-времени — параметр (по умолчанию текущий UTC-год), время в UTC.
- Модель Claude задаётся `SENTINEL_MODEL`, по умолчанию `claude-sonnet-5-5`.
