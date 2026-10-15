# Project skills

Кастомные скиллы Claude Code для SentinelLens. Каждый скилл — папка с `SKILL.md`
(frontmatter `name` + `description`, затем инструкции).

```
.claude/skills/
└── <skill-name>/
    └── SKILL.md
```

Правила для скиллов этого проекта наследуют `CLAUDE.md`: никаких реальных логов,
ключей и сетевых вызовов без подтверждения; тестовые данные — только синтетика
из документационных IP-диапазонов.
