(function (global) {
  const COLLECTION_VERSION = 2;
  const STORAGE_KEY = 'pantene-foodie-journey-collection-v2';
  const LEGACY_KEYS = [
    'pantene-foodie-journey-admin-favorites-v1',
  ];

  const STATUS = Object.freeze({
    WANT_TO_GO: 'want_to_go',
    VISITED: 'visited',
    FAVORITE: 'favorite',
    NOT_CONSIDERING: 'not_considering',
  });

  const STATUS_ORDER = [
    STATUS.WANT_TO_GO,
    STATUS.VISITED,
    STATUS.FAVORITE,
    STATUS.NOT_CONSIDERING,
  ];

  const STATUS_META = Object.freeze({
    [STATUS.WANT_TO_GO]: {
      label: '想去',
      hint: '先收起來再約人',
    },
    [STATUS.VISITED]: {
      label: '已去過',
      hint: '去完可以補感想',
    },
    [STATUS.FAVORITE]: {
      label: '最愛',
      hint: '最想回訪',
    },
    [STATUS.NOT_CONSIDERING]: {
      label: '暫不考慮',
      hint: '之後再決定',
    },
  });

  function createStorageAdapter(storage) {
    const memory = {};
    return {
      read(key) {
        try {
          if (storage && typeof storage.getItem === 'function') {
            return storage.getItem(key);
          }
        } catch (_) {}
        return Object.prototype.hasOwnProperty.call(memory, key) ? memory[key] : null;
      },
      write(key, value) {
        try {
          if (storage && typeof storage.setItem === 'function') {
            storage.setItem(key, value);
            return;
          }
        } catch (_) {}
        memory[key] = String(value);
      },
      remove(key) {
        try {
          if (storage && typeof storage.removeItem === 'function') {
            storage.removeItem(key);
            return;
          }
        } catch (_) {}
        delete memory[key];
      },
    };
  }

  function nowIso() {
    return new Date().toISOString();
  }

  function clone(value) {
    if (typeof structuredClone === 'function') {
      try {
        return structuredClone(value);
      } catch (_) {}
    }
    return JSON.parse(JSON.stringify(value));
  }

  function toText(value) {
    if (value === null || value === undefined) return '';
    return String(value).trim();
  }

  function slugify(value) {
    return toText(value)
      .toLowerCase()
      .replace(/['’]/g, '')
      .replace(/[^a-z0-9\u4e00-\u9fff]+/gi, '-')
      .replace(/^-+|-+$/g, '') || '';
  }

  function parseJSON(value) {
    if (!value) return null;
    try {
      return JSON.parse(value);
    } catch (_) {
      return null;
    }
  }

  function defaultNotes() {
    return {
      dishes: '',
      withWho: '',
      occasion: '',
      plannedDate: '',
    };
  }

  function defaultCollection() {
    return {
      version: COLLECTION_VERSION,
      updatedAt: nowIso(),
      entries: {},
      lists: [],
    };
  }

  function normalizeStatus(value) {
    const text = toText(value);
    if (STATUS_ORDER.includes(text)) return text;
    if (text === 'favorite' || text === 'favourite' || text === '最愛') return STATUS.FAVORITE;
    if (text === 'visited' || text === '已去過') return STATUS.VISITED;
    if (text === 'not_considering' || text === '暫不考慮') return STATUS.NOT_CONSIDERING;
    if (text === 'want_to_go' || text === '想去' || text === '收藏') return STATUS.WANT_TO_GO;
    return STATUS.WANT_TO_GO;
  }

  function normalizeNotes(value) {
    const notes = defaultNotes();
    if (!value || typeof value !== 'object') {
      if (typeof value === 'string') {
        notes.dishes = toText(value);
      }
      return notes;
    }
    notes.dishes = toText(value.dishes || value.wantToTry || value.dish || value.note || '');
    notes.withWho = toText(value.withWho || value.with_whom || value.party || '');
    notes.occasion = toText(value.occasion || value.scene || value.suitableOccasion || '');
    notes.plannedDate = toText(value.plannedDate || value.date || value.planDate || '');
    return notes;
  }

  function normalizeEntry(value, fallbackStatus) {
    const now = nowIso();
    if (!value || typeof value !== 'object') {
      return {
        status: normalizeStatus(value || fallbackStatus),
        notes: defaultNotes(),
        listIds: [],
        createdAt: now,
        updatedAt: now,
      };
    }
    const listIds = Array.isArray(value.listIds)
      ? value.listIds.map(toText).filter(Boolean)
      : Array.isArray(value.list_ids)
        ? value.list_ids.map(toText).filter(Boolean)
        : [];
    return {
      status: normalizeStatus(value.status || fallbackStatus),
      notes: normalizeNotes(value.notes || value.privateNotes || value.private_note || value),
      listIds: Array.from(new Set(listIds)),
      createdAt: toText(value.createdAt || value.created_at) || now,
      updatedAt: toText(value.updatedAt || value.updated_at) || now,
    };
  }

  function normalizeList(value, index) {
    const now = nowIso();
    if (!value || typeof value !== 'object') {
      const name = toText(value);
      return {
        id: slugify(name) || `list-${index + 1}`,
        name,
        createdAt: now,
        updatedAt: now,
      };
    }
    const name = toText(value.name || value.title || value.label);
    return {
      id: toText(value.id) || slugify(name) || `list-${index + 1}`,
      name,
      createdAt: toText(value.createdAt || value.created_at) || now,
      updatedAt: toText(value.updatedAt || value.updated_at) || now,
    };
  }

  function normalizeCollection(raw) {
    const base = defaultCollection();
    const source = typeof raw === 'string' ? parseJSON(raw) : raw;
    if (!source || typeof source !== 'object') {
      return base;
    }

    const entries = {};
    const rawEntries = source.entries || source.restaurants || source.collection || {};
    if (Array.isArray(source)) {
      source.forEach((item, index) => {
        const id = toText(
          item && typeof item === 'object'
            ? (item.id || item.restaurantId || item.placeId)
            : item,
        ) || `restaurant-${index + 1}`;
        entries[id] = normalizeEntry(item, STATUS.WANT_TO_GO);
      });
    } else if (rawEntries && typeof rawEntries === 'object' && !Array.isArray(rawEntries)) {
      Object.entries(rawEntries).forEach(([id, item]) => {
        const safeId = toText(id);
        if (!safeId) return;
        entries[safeId] = normalizeEntry(item, STATUS.WANT_TO_GO);
      });
    }

    if (Array.isArray(source.favorites)) {
      source.favorites.forEach((item, index) => {
        const id = toText(item && (item.id || item.restaurantId || item.placeId || item.key || item.slug))
          || (typeof item === 'string' ? toText(item) : '')
          || `legacy-favorite-${index + 1}`;
        if (!id) return;
        const existing = entries[id];
        const payload = item && typeof item === 'object' ? item : { status: STATUS.WANT_TO_GO };
        entries[id] = normalizeEntry(existing ? { ...existing, ...payload } : payload, STATUS.WANT_TO_GO);
        if (!entries[id].status) entries[id].status = STATUS.WANT_TO_GO;
      });
    }

    const lists = Array.isArray(source.lists)
      ? source.lists.map(normalizeList)
      : Array.isArray(source.customLists)
        ? source.customLists.map(normalizeList)
        : [];

    const updatedAt = toText(source.updatedAt || source.updated_at) || nowIso();
    return {
      version: COLLECTION_VERSION,
      updatedAt,
      entries,
      lists,
    };
  }

  function createStore(options = {}) {
    const adapter = options.adapter || createStorageAdapter(options.storage || global.localStorage);
    const storageKey = options.storageKey || STORAGE_KEY;
    let cache = null;

    function load() {
      if (cache) return clone(cache);
      const primary = normalizeCollection(adapter.read(storageKey));
      if (primary && Object.keys(primary.entries).length > 0) {
        cache = primary;
        return clone(cache);
      }
      for (let i = 0; i < LEGACY_KEYS.length; i += 1) {
        const legacy = normalizeCollection(adapter.read(LEGACY_KEYS[i]));
        if (legacy && Object.keys(legacy.entries).length > 0) {
          cache = legacy;
          save(cache);
          return clone(cache);
        }
      }
      cache = defaultCollection();
      save(cache);
      return clone(cache);
    }

    function save(nextState) {
      const normalized = normalizeCollection(nextState);
      normalized.version = COLLECTION_VERSION;
      normalized.updatedAt = nowIso();
      cache = normalized;
      adapter.write(storageKey, JSON.stringify(normalized));
      return clone(cache);
    }

    function update(mutator) {
      const current = load();
      const working = clone(current);
      const next = mutator(working) || working;
      return save(next);
    }

    function ensureEntry(state, restaurantId) {
      const id = toText(restaurantId);
      if (!id) return null;
      if (!state.entries[id]) {
        const now = nowIso();
        state.entries[id] = {
          status: STATUS.WANT_TO_GO,
          notes: defaultNotes(),
          listIds: [],
          createdAt: now,
          updatedAt: now,
        };
      }
      return state.entries[id];
    }

    function getRestaurant(restaurantId) {
      const state = load();
      const id = toText(restaurantId);
      if (!id || !state.entries[id]) return null;
      return clone({ id, ...state.entries[id] });
    }

    function getRestaurants() {
      const state = load();
      return Object.entries(state.entries).map(([id, value]) => ({ id, ...clone(value) }));
    }

    function setStatus(restaurantId, status) {
      return update((state) => {
        const entry = ensureEntry(state, restaurantId);
        if (!entry) return state;
        entry.status = normalizeStatus(status);
        entry.updatedAt = nowIso();
        return state;
      });
    }

    function setNotes(restaurantId, notes) {
      return update((state) => {
        const entry = ensureEntry(state, restaurantId);
        if (!entry) return state;
        entry.notes = normalizeNotes(notes);
        entry.updatedAt = nowIso();
        return state;
      });
    }

    function toggleListMembership(restaurantId, listId) {
      return update((state) => {
        const entry = ensureEntry(state, restaurantId);
        const targetListId = toText(listId);
        if (!entry || !targetListId) return state;
        const listExists = state.lists.some((item) => item.id === targetListId);
        if (!listExists) return state;
        const nextIds = new Set(Array.isArray(entry.listIds) ? entry.listIds : []);
        if (nextIds.has(targetListId)) nextIds.delete(targetListId);
        else nextIds.add(targetListId);
        entry.listIds = Array.from(nextIds);
        entry.updatedAt = nowIso();
        return state;
      });
    }

    function createList(name) {
      const listName = toText(name);
      if (!listName) {
        return { created: false, list: null };
      }
      let result = null;
      update((state) => {
        const existing = state.lists.find((item) => item.name === listName);
        if (existing) {
          result = { created: false, list: clone(existing) };
          return state;
        }
        const now = nowIso();
        const baseId = slugify(listName) || `list-${state.lists.length + 1}`;
        let id = baseId;
        let suffix = 2;
        while (state.lists.some((item) => item.id === id)) {
          id = `${baseId}-${suffix}`;
          suffix += 1;
        }
        const list = {
          id,
          name: listName,
          createdAt: now,
          updatedAt: now,
        };
        state.lists.push(list);
        result = { created: true, list: clone(list) };
        return state;
      });
      return result || { created: false, list: null };
    }

    function renameList(listId, name) {
      const targetId = toText(listId);
      const nextName = toText(name);
      if (!targetId || !nextName) return null;
      return update((state) => {
        const list = state.lists.find((item) => item.id === targetId);
        if (!list) return state;
        list.name = nextName;
        list.updatedAt = nowIso();
        return state;
      });
    }

    function deleteList(listId) {
      const targetId = toText(listId);
      if (!targetId) return false;
      let removed = false;
      update((state) => {
        const nextLists = state.lists.filter((item) => item.id !== targetId);
        if (nextLists.length === state.lists.length) return state;
        removed = true;
        state.lists = nextLists;
        Object.values(state.entries).forEach((entry) => {
          entry.listIds = Array.isArray(entry.listIds)
            ? entry.listIds.filter((id) => id !== targetId)
            : [];
          entry.updatedAt = nowIso();
        });
        return state;
      });
      return removed;
    }

    function hasRestaurant(restaurantId) {
      const state = load();
      return Boolean(state.entries[toText(restaurantId)]);
    }

    function clearRestaurant(restaurantId) {
      const id = toText(restaurantId);
      if (!id) return false;
      let removed = false;
      update((state) => {
        if (!state.entries[id]) return state;
        delete state.entries[id];
        removed = true;
        return state;
      });
      return removed;
    }

    function getLists() {
      return load().lists.map((item) => clone(item));
    }

    function getStatusLabel(status) {
      const normalized = normalizeStatus(status);
      return STATUS_META[normalized] ? STATUS_META[normalized].label : STATUS_META[STATUS.WANT_TO_GO].label;
    }

    function getStatusMeta(status) {
      const normalized = normalizeStatus(status);
      return STATUS_META[normalized] || STATUS_META[STATUS.WANT_TO_GO];
    }

    return {
      version: COLLECTION_VERSION,
      storageKey,
      load,
      save,
      update,
      getRestaurant,
      getRestaurants,
      setStatus,
      setNotes,
      toggleListMembership,
      createList,
      renameList,
      deleteList,
      hasRestaurant,
      clearRestaurant,
      getLists,
      getStatusLabel,
      getStatusMeta,
    };
  }

  global.PanteneRestaurantCollectionStore = {
    COLLECTION_VERSION,
    STORAGE_KEY,
    LEGACY_KEYS,
    STATUS,
    STATUS_META,
    STATUS_ORDER,
    createStorageAdapter,
    normalizeCollection,
    createStore,
  };
})(window);
