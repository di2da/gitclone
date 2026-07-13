(function (global) {
  const VERIFICATION_STATUS = Object.freeze({
    VERIFIED: 'verified',
    PENDING: 'pending',
    ARCHIVED: 'archived',
  });

  const allowedStatuses = new Set(Object.values(VERIFICATION_STATUS));

  function slugify(value) {
    return String(value || '')
      .trim()
      .toLowerCase()
      .replace(/['’]/g, '')
      .replace(/[^a-z0-9\u4e00-\u9fff]+/gi, '-')
      .replace(/^-+|-+$/g, '') || 'restaurant';
  }

  function toText(value) {
    if (value === null || value === undefined) return '';
    return String(value).trim();
  }

  function toNullableNumber(value) {
    if (value === null || value === undefined || value === '') return null;
    const num = Number(value);
    return Number.isFinite(num) ? num : null;
  }

  function toStringArray(value) {
    if (Array.isArray(value)) {
      return value.map(toText).filter(Boolean);
    }
    if (value === null || value === undefined || value === '') {
      return [];
    }
    return [toText(value)].filter(Boolean);
  }

  function normalizeOpeningHours(value) {
    if (Array.isArray(value)) {
      return value
        .map((item) => (item && typeof item === 'object'
          ? {
              day: toText(item.day),
              open: toText(item.open),
              close: toText(item.close),
              note: toText(item.note),
            }
          : null))
        .filter(Boolean);
    }
    if (value && typeof value === 'object') {
      return Object.entries(value).map(([day, hours]) => ({
        day: toText(day),
        open: toText(hours && hours.open),
        close: toText(hours && hours.close),
        note: toText(hours && hours.note),
      }));
    }
    if (typeof value === 'string' && value.trim()) {
      return [value.trim()];
    }
    return [];
  }

  function normalizeStatus(value) {
    const status = toText(value);
    if (allowedStatuses.has(status)) return status;
    return VERIFICATION_STATUS.PENDING;
  }

  function validateRestaurant(restaurant) {
    const missing = [];
    if (!toText(restaurant.id)) missing.push('id');
    if (!toText(restaurant.nameZh)) missing.push('nameZh');
    if (!allowedStatuses.has(toText(restaurant.verificationStatus))) missing.push('verificationStatus');
    return {
      valid: missing.length === 0,
      missing,
    };
  }

  function normalizeRestaurant(record, index = 0) {
    const nameZh = toText(record && (record.nameZh || record.name)) || '';
    const district = toText(record && (record.district || record.area)) || '';
    const description = toText(record && (record.description || record.note)) || '';
    const panteneNote = toText(record && (record.panteneNote || record.why)) || '';
    const suitableOccasions = toStringArray(record && record.suitableOccasions).length
      ? toStringArray(record.suitableOccasions)
      : toStringArray(record && (record.bestFor ? record.bestFor.split('/').map((part) => part.trim()) : []));
    const verificationStatus = normalizeStatus(record && record.verificationStatus);
    const now = new Date().toISOString();
    const createdAt = toText(record && record.createdAt) || now;
    const updatedAt = toText(record && record.updatedAt) || createdAt;
    const normalized = {
      id: toText(record && record.id) || slugify(nameZh || `restaurant-${index + 1}`),
      nameZh,
      nameEn: toText(record && record.nameEn),
      branchName: toText(record && record.branchName),
      cuisine: toText(record && record.cuisine),
      district,
      address: toText(record && record.address) || null,
      latitude: toNullableNumber(record && record.latitude),
      longitude: toNullableNumber(record && record.longitude),
      googlePlaceId: toText(record && record.googlePlaceId) || null,
      priceMin: toNullableNumber(record && record.priceMin),
      priceMax: toNullableNumber(record && record.priceMax),
      openingHours: normalizeOpeningHours(record && record.openingHours),
      phone: toText(record && record.phone) || null,
      bookingUrl: toText(record && record.bookingUrl) || null,
      officialUrl: toText(record && record.officialUrl) || null,
      instagramUrl: toText(record && record.instagramUrl) || null,
      description,
      panteneNote,
      suitableOccasions,
      signatureDishes: toStringArray(record && record.signatureDishes),
      coverImage: toText(record && record.coverImage) || null,
      verificationStatus,
      sourceUrl: toText(record && record.sourceUrl) || null,
      verifiedAt: verificationStatus === VERIFICATION_STATUS.VERIFIED ? (toText(record && record.verifiedAt) || createdAt) : null,
      createdAt,
      updatedAt,
    };

    normalized.name = normalized.nameZh;
    normalized.area = normalized.district;
    normalized.note = normalized.description;
    normalized.why = normalized.panteneNote;
    normalized.bestFor = normalized.suitableOccasions.join(' / ');
    normalized.mapQuery = toText(record && record.mapQuery) || [normalized.nameZh, normalized.district].filter(Boolean).join(' ');
    normalized.validation = validateRestaurant(normalized);
    return normalized;
  }

  function normalizeCatalog(list) {
    if (!Array.isArray(list)) return [];
    return list.map((item, index) => normalizeRestaurant(item, index));
  }

  function filterRestaurants(list, mode = 'public') {
    const catalog = normalizeCatalog(list);
    if (mode === 'public') {
      return catalog.filter((restaurant) => restaurant.verificationStatus === VERIFICATION_STATUS.VERIFIED);
    }
    return catalog.filter((restaurant) => restaurant.verificationStatus !== VERIFICATION_STATUS.ARCHIVED);
  }

  function getRecommendableRestaurants(list, mode = 'public') {
    return filterRestaurants(list, mode);
  }

  function getEmptyStateMessage(mode = 'public') {
    return mode === 'public'
      ? '暫時未有已確認餐廳，請等管理模式完成核實。'
      : '暫時未有可用餐廳資料。';
  }

  global.PanteneRestaurantModel = {
    VERIFICATION_STATUS,
    normalizeRestaurant,
    normalizeCatalog,
    filterRestaurants,
    getRecommendableRestaurants,
    getEmptyStateMessage,
    validateRestaurant,
  };
})(window);
