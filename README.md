# SentinelLens

Учебный AI-assisted SOC triage tool для SSH-логов. **Это MVP, а не production SIEM.**

SentinelLens разбирает синтетический `auth.log`, применяет детерминированные правила обнаружения и
возвращает JSON-findings с ID событий-доказательств (evidence). Поверх findings можно запросить
необязательный triage от Claude. Без LLM и без API-ключа инструмент работает полностью.

```
auth.log → parser → AuthEvent[] → detections → Finding[] → triage (optional) → AnalysisReport
```

## Стек

Python 3.11+, FastAPI, Pydantic v2, pytest, Anthropic SDK (только для опционального triage).
UI нет: используется встроенный Swagger на `/docs`.

## Возможности

- **Парсер** `Failed password` / `Accepted password`, включая `invalid user`. Event ID детерминирован
  от номера строки (`evt-000042`). Нераспознанные строки считаются в `lines_skipped`, а не роняют разбор.
- **Два правила**, без I/O и без LLM:

  | Правило | Условие | Severity |
  |---|---|---|
  | `brute_force` | ≥ 5 неудачных входов с одного `src_ip` на одном `host` в скользящем окне 5 минут (граница включена). Одна серия — один finding. | `medium` |
  | `success_after_failures` | `Accepted` после ≥ 3 неудач с тем же `host + src_ip + username`, неудачи строго раньше (по времени, затем по номеру строки), не дальше 10 минут. Каждый успешный вход — отдельный finding. | `high` |

- **Triage** в трёх режимах: `none` (по умолчанию), `mock`, `claude`.
- **Каждый finding ссылается на evidence event IDs**, по которым его можно проверить вручную.

## Запуск

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

pytest                                  # все тесты, сеть не нужна

uvicorn app.main:app --reload           # затем http://127.0.0.1:8000/docs
```

Опциональные переменные окружения (нужны только для `triage=claude`):

| Переменная | Назначение | По умолчанию |
|---|---|---|
| `ANTHROPIC_API_KEY` | ключ Anthropic API, читается только из окружения | не задан |
| `SENTINEL_MODEL` | модель для triage | `claude-sonnet-5-5` |

## API

### `GET /health`

Возвращает `{"status": "ok"}`.

### `POST /analyze`

Multipart-форма:

| Поле | Тип | Описание |
|---|---|---|
| `file` | файл | `auth.log` в формате syslog, UTF-8. Максимум 1 МиБ, иначе `413`. |
| `triage` | `none` \| `mock` \| `claude` | режим triage, по умолчанию `none` |
| `year` | int, 2000–2100 | год для времени (в syslog его нет), по умолчанию текущий UTC-год |

Время трактуется как UTC. Неверные значения полей дают `422`.

### Пример запроса

```powershell
curl.exe -X POST http://127.0.0.1:8000/analyze `
  -F "file=@tests/fixtures/auth_sample.log" `
  -F "triage=mock" `
  -F "year=2026"
```

### Структура ответа

Ответ получен на `tests/fixtures/auth_sample.log` в режиме `mock`; для краткости оставлено по одному
элементу в списках.

```json
{
  "triage_mode": "mock",
  "lines_total": 23,
  "events_parsed": 20,
  "lines_skipped": 3,
  "findings": [
    {
      "finding_id": "fnd-0001",
      "rule_id": "brute_force",
      "severity": "medium",
      "title": "SSH brute force: 6 failed logins from 203.0.113.5",
      "host": "web01",
      "src_ip": "203.0.113.5",
      "usernames": ["admin", "root"],
      "first_seen": "2026-10-15T10:00:01Z",
      "last_seen": "2026-10-15T10:01:30Z",
      "evidence_event_ids": ["evt-000001", "evt-000002", "evt-000003", "evt-000004", "evt-000005", "evt-000006"]
    }
  ],
  "triage": [
    {
      "finding_id": "fnd-0001",
      "source": "mock",
      "status": "ok",
      "model": null,
      "disclaimer": "MOCK: placeholder output, not real LLM analysis.",
      "output": {
        "finding_id": "fnd-0001",
        "verdict": "suspicious",
        "confidence": 0.5,
        "summary": "Placeholder triage for rule brute_force.",
        "rationale": "Fixed mock text. No model analyzed this finding.",
        "cited_event_ids": ["evt-000001", "evt-000002", "evt-000003"],
        "recommended_actions": ["Review the evidence events manually."]
      },
      "error": null
    }
  ]
}
```

| Поле | Смысл |
|---|---|
| `lines_total` / `events_parsed` / `lines_skipped` | сколько строк прочитано, разобрано и пропущено |
| `findings[]` | срабатывания правил; `finding_id` сквозной (`fnd-0001`, `fnd-0002`, …), порядок хронологический |
| `findings[].evidence_event_ids` | события, из-за которых сработало правило |
| `triage[]` | по одному результату на finding; пустой при `triage=none` |
| `triage[].source` | `mock` или `llm`. Mock всегда содержит `disclaimer` и не выдаётся за анализ модели |
| `triage[].status` | `ok` или `error`; при `error` заполнено `error`, `output` пуст |
| `triage[].output.verdict` | `likely_malicious`, `suspicious`, `likely_benign` или `insufficient_evidence` |

## Режимы triage

| Режим | Что происходит |
|---|---|
| `none` | только правила, `triage` пуст |
| `mock` | фиксированный текст-заглушка с `source="mock"` и disclaimer; сеть не используется |
| `claude` | запрос к Claude по каждому finding, ответ проверяется (см. ниже) |

Если `ANTHROPIC_API_KEY` не задан, запрос не падает: findings возвращаются, а в `triage` у каждого
finding статус `error` с понятным сообщением.

## Безопасность

- **Логи — недоверенные данные.** Всё, что взято из логов (имена пользователей, хосты, title finding'а),
  передаётся модели только внутри блока `<untrusted_log_data>`; символ `<` внутри блока экранируется,
  поэтому строка из лога не может его закрыть. Системный промпт требует игнорировать любые инструкции
  из этого блока.
- **Ответ LLM проверяется.** Он валидируется схемой `LLMTriageOutput` (лишние поля запрещены), затем
  проверяется, что `finding_id` совпадает, а `cited_event_ids` — подмножество evidence этого finding.
  Невалидный ответ даёт результат со статусом `error`, а не исключение.
- **Никаких действий.** Нет блокировок IP и вызовов `subprocess`. `recommended_actions` — только текст
  для аналитика.
- **Текст логов не возвращается** в ответе API: наружу идут только разобранные поля и ID событий.
- Ключ берётся только из переменной окружения; в тестах реальный API и сеть не используются.

## MITRE ATT&CK (ориентировочное соответствие)

Маппинг приведён для справки аналитику; в JSON-ответ он не включается.

| Правило | Техника | Тактика |
|---|---|---|
| `brute_force` | [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/) (по картине — T1110.001 Password Guessing или T1110.003 Password Spraying) | Credential Access |
| `success_after_failures` | T1110 Brute Force → [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/); при входе по SSH — также [T1021.004 Remote Services: SSH](https://attack.mitre.org/techniques/T1021/004/) | Credential Access, Initial Access, Lateral Movement |

Правило фиксирует только признаки в логе. Какая именно подтехника и тактика здесь применимы,
решает аналитик по контексту.

## Структура проекта

```
app/
  models.py       Pydantic-модели: AuthEvent, Finding, LLMTriageOutput, TriageResult, AnalysisReport
  parser.py       auth.log → AuthEvent
  detections.py   правила и run_detections
  triage.py       none / mock / claude, валидация ответа LLM
  main.py         FastAPI: /health, /analyze
tests/
  fixtures/auth_sample.log   синтетический лог (IP из 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
PLAN.md           порядок работ
CLAUDE.md         правила проекта для Claude Code
```

## Ограничения

- Учебный MVP; для разбора реальных инцидентов не предназначен.
- Только SSH-события `Failed password` и `Accepted password`. Вход по ключу, `Invalid user` без пароля,
  PAM, sudo и прочее не разбираются и считаются пропущенными строками.
- Правила привязаны к `host + src_ip` (и `username` для `success_after_failures`). Распределённый
  перебор с множества IP и password spraying по разным IP не объединяются.
- Параметр `year` — единственный источник года: на стыке годов (декабрь → январь) логи придётся
  разбивать вручную.
- Время считается UTC; часовые пояса в syslog не учитываются.
- Лимит файла 1 МиБ проверяется после приёма загрузки, это не защита от больших тел запроса на
  уровне сервера.
- Triage — вспомогательная подсказка, а не вердикт. Результаты `claude` не детерминированы, а `mock` —
  заглушка.
- Реальный вызов Claude автоматическими тестами не проверяется: они используют фейковый клиент.
