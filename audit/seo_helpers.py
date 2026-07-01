def has_meta(page_data, key):
    return key.lower() in page_data["meta"]


def get_meta(page_data, key):
    return page_data["meta"].get(key.lower())


def heading_count(page_data, level):
    return len(page_data["headings"].get(level.lower(), []))