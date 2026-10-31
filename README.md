# Auth Starter

Минимальный проект регистрации и входа по почте и паролю на Node.js. Есть профиль и выход из аккаунта; почтовые коды и OAuth не используются.

## Запуск

Нужен Node.js 20 или новее.

```powershell
Copy-Item .env.example .env
node server.js
```

Открой http://localhost:3000. Пользователи сохраняются в `data/users.json`; каталог с данными исключён из Git.

