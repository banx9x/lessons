import observer from "./observer.js";
import { parseURL } from "./utils.js";

let link = (url, isActive, page) => {
    if (page < 1 || page > url.totalPages) {
        return null;
    }

    let li = document.createElement("li");
    li.className = `page-item ${isActive ? "active" : ""}`;

    let link = document.createElement("button");
    link.className = "page-link";
    link.innerHTML = page;

    if (!isActive) {
        link.onclick = function () {
            url.params.set("page", page);
            history.pushState(null, null, "?" + url.params.toString());
            observer.notify("render homepage");
        };
    }

    li.appendChild(link);
    return li;
};

const nav = document.querySelector(".nav");

export default function (students) {
    let url = parseURL();
    url.totalPages = Math.ceil(students.length / url.limit);

    nav.innerHTML = "";

    if (url.totalPages > 1) {
        let ul = document.createElement("ul");
        ul.className = "pagination justify-content-center";

        for (let i = 1; i <= url.totalPages; i++) {
            let isActive = url.page == i;
            ul.appendChild(link(url, isActive, i));
        }

        nav.appendChild(ul);
    }
}
