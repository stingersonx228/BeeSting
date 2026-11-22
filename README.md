# 🐝 BeeSting

**Скилл для Claude Code: аудит и защита сайтов «статика + Supabase + Vercel».**

> *EN: A Claude Code skill that audits and hardens static sites backed by Supabase — RLS and grants, SECURITY DEFINER RPCs, migrations verified on a local Supabase-like Postgres, strict CSP without `unsafe-inline` + SRI, Cloudflare Turnstile gate via Edge Function, and staff 2FA (aal2). Docs are in Russian.*

Anon key и URL проекта Supabase публичны, поэтому любой может вызвать из консоли всё, что разрешено ролям `anon` и `authenticated`, в обход сайта. BeeSting учит агента искать такие дыры в базе, закрывать их миграцией, проверять SQL локально до того, как его запустят на проде, и доводить фронт до строгой CSP.

## Что внутри

| | |
|---|---|
| `SKILL.md` | Процесс: карта проекта → аудит → миграция-исправление → проверка → передача владельцу базы |
| `references/supabase-audit.md` | Чек-лист RLS, грантов, SECURITY DEFINER, view, realtime, бизнес-логики и клиента; шаблон миграции |
| `references/sql-verification.md` | Как проверять миграции на локальном стенде и писать сценарии «свой может / чужой нет» |
| `references/csp-sri.md` | Строгая CSP без `unsafe-inline`, `script-src-attr 'none'`, SRI, заголовки, выкатка через Report-Only |
| `references/turnstile-gate.md` | Антиспам: Turnstile + Edge Function-шлюз + lock-миграция, порядок выкатки и откат |
| `references/staff-mfa.md` | 2FA персонала (TOTP, Supabase MFA) с проверкой `aal2` в базе |
| `scripts/pg-harness/` | Supabase-подобный Postgres 17 (embedded): роли, `auth.uid()/jwt()`, default privileges, аудит прав, сценарии |
| `scripts/csp_scan.mjs` | Находит всё, что мешает строгой CSP: inline-скрипты, `on*`-атрибуты, `javascript:`, CDN без SRI |
| `scripts/sri.sh` | SRI-хэши для файлов с CDN |
| `assets/` | Шаблоны: `turnstile-gate.ts` (Edge Function), `staff-mfa.js` (экран 2FA для панели) |
| `evals/` | 3 тест-кейса на учебном проекте с заложенными дырами + оценщик базы |

## Установка

```bash
git clone https://github.com/stingersonx228/BeeSting.git ~/.claude/skills/beesting
```

Скилл срабатывает сам, когда в проекте есть Supabase и вы просите что-то вроде «проверь безопасность», «почини RLS», «закрой RPC от anon», «сделай нормальную CSP», «добавь капчу на заказы», «включи 2FA для админки». Можно вызвать явно: `/beesting`.

Для стенда нужен Node.js 18+ и npm. Он ставится во временную папку, в проект ничего не попадает:

```bash
cp -r ~/.claude/skills/beesting/scripts/pg-harness /tmp/pgh && sh /tmp/pgh/setup.sh
node /tmp/pgh/harness.mjs --repo ./my-site                                   # порядок миграций из DEPLOY.md/README.md
node /tmp/pgh/harness.mjs --repo ./my-site --twice fix.sql --scenario checks.mjs
node ~/.claude/skills/beesting/scripts/csp_scan.mjs ./my-site
```

Пример отчёта стенда:

```
✓ применён schema.sql
✓ применён promo.sql
⚠ Таблицы public без RLS: 1
   - staff (anon: select+write)
⚠ SECURITY DEFINER без set search_path: 2
⚠ Функции, доступные через /rest/v1/rpc (проверить каждую): 3
   - mark_paid(bigint) — anon+authenticated, через PUBLIC, DEFINER, без проверки личности
⚠ View без security_invoker, читаемые anon/authenticated (обходят RLS): 1
```

## Бенчмарк

Три задачи на учебном сайте пиццерии, по одному прогону со скиллом и без (Claude Opus):

| Задача | Со скиллом | Без |
|---|---|---|
| Аудит безопасности | 10/10 | 9/10 |
| Миграция-исправление с проверкой | 11/11 | 10/11 |
| Строгая CSP | 7/8 | 6/8 |
| **Итого** | **96%** | **85%** |

Со скиллом агент подтверждает атаки на стенде, а не только по коду, находит «ленивые» вызовы supabase-js без `await`, отдаёт SQL целиком для SQL Editor, прикладывает откат и порядок выкатки.

## Принципы

- Защита живёт в базе; проверки в JS только для удобства.
- Применённые миграции не редактируются: исправление идёт новым идемпотентным файлом.
- Каждый SQL до передачи проходит на стенде со всеми предыдущими миграциями, повторно и со сценариями.
- Каждый шаг выкатки оставляет сайт рабочим и имеет откат.
- Ничего не применяется к проду без явной просьбы.

## Лицензия

[MIT](LICENSE)
