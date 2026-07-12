# Data Model

## User

- id
- name
- role: owner | partner | friend
- avatar
- created_at

## Place

- id
- name
- address
- map_url
- category
- price_level
- tags
- rating

## Comment

- id
- target_type: place | favorite | note
- target_id
- author_name
- body
- created_at

## Favorite

- id
- user_id
- place_id
- note
- created_at

## Tag

- id
- name
- color
