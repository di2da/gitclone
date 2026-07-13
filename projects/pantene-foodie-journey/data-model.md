# Data Model

## Restaurant

Unified schema for restaurant records in Pantene's Foodie Journey.

- id
- nameZh
- nameEn
- branchName
- cuisine
- district
- address
- latitude
- longitude
- googlePlaceId
- priceMin
- priceMax
- openingHours
- phone
- bookingUrl
- officialUrl
- instagramUrl
- description
- panteneNote
- suitableOccasions
- signatureDishes
- coverImage
- verificationStatus: verified | pending | archived
- sourceUrl
- verifiedAt
- createdAt
- updatedAt

## Compatibility

- Legacy `Place` records are migrated through `restaurant-model.js`.
- Existing fields such as `name`, `area`, `note`, `bestFor`, `why`, and `mapQuery` are kept as compatibility aliases.
- Missing sensitive fields are stored as `null` or empty arrays/strings and never invented.

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
