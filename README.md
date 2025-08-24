

Кастомная система аутентификации и авторизации на Django + DRF

Функционал
- Регистрация, логин, логаут, профиль
- Роли и права доступа (Role → Permission → Resource)
- Сессии с токенами (хранятся в БД, токен — sha256)
- Ограничение доступа через кастомные DRF permission-классы

Стек
- Django 
- Django REST Framework 
- PostgreSQL

Установка

bash

git clone 
cd auth_system
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python manage.py migrate
python manage.py runserver


 эндпоинты
POST /api/auth/register/

POST /api/auth/login/

POST /api/auth/logout/

GET /api/auth/profile/

GET /api/roles/

POST /api/roles/

POST /api/users/{id}/roles/

POST /api/roles/{id}/permissions/

GET /api/products/