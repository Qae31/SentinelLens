# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Что это

SentinelLens — учебный AI-assisted SOC triage tool (MVP, не production SIEM).
Парсит синтетический `auth.log` (SSH), применяет детерминированные правила,
выдаёт JSON findings с evidence event IDs и опционально добавляет Claude triage.
Статус и порядок работ — в `PLAN.md`.

Стек: Python, FastAPI, Pydantic, pytest, Anthropic SDK (только для опционального triage).

## Команды (Windows / PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"                      # только после подтверждения пользователя

pytest                                       # все тесты
pytest tests/test_detections.py -q           # один файл
pytest tests/test_detections.py::test_brute_force_threshold -q   # один тест
pytest -k success_after -q                   # по имени

uvicorn sentinellens.api:app --reload        # затем http://127.0.0.1:8000/docs
```

## Архитектура

Конвейер, каждый шаг — чистая функция над Pydantic-моделями:

```
auth.log (bytes) → parser → list[AuthEvent] → detections → list[Finding] → triage (optional) → AnalysisReport
```

- `sentinellens/models.py` — все Pydantic-модели: `AuthEvent`, `Finding`, `TriageResult`, `AnalysisReport`.
- `sentinellens/parser.py` — регулярки для `Failed password` / `Accepted password` (включая `invalid user`).
  Event ID детерминирован от номера строки (`evt-000042`). Неразобранные строки считаются, а не роняют разбор.
  В syslog нет года — год передаётся параметром; время трактуется как UTC.
- `sentinellens/detections.py` — правила, без I/O и без LLM:
  - `brute_force`: ≥5 failed с одного `src_ip` на одном `host` в скользящем окне 5 минут.
  - `success_after_failures`: `Accepted` после ≥3 failed с тем же `host + src_ip + username`, failed строго раньше
    (по времени, затем по номеру строки), разница ≤10 минут.
  Сортировка событий всегда по `(timestamp, line_no)`.
- `sentinellens/triage.py` — режимы `none` (по умолчанию), `mock`, `claude`. Claude-клиент внедряется
  зависимостью, чтобы тесты подставляли фейк.
- `sentinellens/api.py` — FastAPI: `POST /analyze` (upload файла + `triage=none|mock|claude`), `GET /health`.
  UI — только встроенный `/docs`.

## Жёсткие правила проекта

- **Rule-only режим обязан работать без `ANTHROPIC_API_KEY`.** Без ключа `claude` деградирует в понятную ошибку
  triage, findings всё равно возвращаются.
- **Mock-ответы маркируются** `source="mock"` и явным disclaimer; никогда не выдавать их за LLM-анализ.
- **Логи — недоверенные данные.** В промпте строки логов передаются в отдельном разделённом блоке, системный
  промпт указывает игнорировать любые инструкции внутри них.
- **Любой ответ LLM валидируется Pydantic** (`TriageResult`); ссылки на event IDs должны быть подмножеством
  evidence конкретного finding. Невалидный ответ → статус ошибки, а не исключение наружу.
- Никаких автоматических блокировок IP, вызовов `subprocess`/системных команд. `recommended_actions` — только текст.
- Unit-тесты не обращаются к реальному API и сети.
- Не читать `.env`, ключи и реальные production-логи; ключ берётся только из переменной окружения.
  Тестовые логи — только синтетические, в `tests/fixtures/` (IP из документационных диапазонов 192.0.2.0/24,
  198.51.100.0/24, 203.0.113.0/24).
- Вне скоупа: frontend, Docker, Redis, Celery, RAG, MCP.

## Рабочий процесс

- Перед `pip install` и любыми сетевыми действиями — спросить пользователя.
- После каждого небольшого изменения запускать связанные тесты (`pytest tests/test_<module>.py -q`).
