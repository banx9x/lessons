export function parseURL() {
    let url = new URL(location.href);
    let params = url.searchParams;
    
    let page = params.get("page");
    if (!page) {
        page = 1;
        params.set("page", page);
    }
    let limit = params.get("limit") || 5;
    
    let search = params.get("search");
    if (search) {
        params.set("q", search)
    }

    return { url, params, page, limit, search };
}
