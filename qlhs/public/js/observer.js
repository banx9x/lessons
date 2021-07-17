import render, { renderStudent } from "./render.js";
import pagination from "./pagination.js";
import { parseURL } from "./utils.js";

class Observer {
    constructor() {
        this.list = {};
    }

    add(event, callback) {
        if (!this.list[event]) {
            this.list[event] = [];
        }

        this.list[event].push(callback);
    }

    notify(event, data) {
        if (!this.list[event]) {
            return;
        }

        this.list[event].forEach((f) => {
            f(data);
        });
    }

    remove(event, callback) {
        if (!this.list[event]) {
            return;
        }

        this.list[event] = this.list[event].filter((f) => f != callback);
    }
}

const observer = new Observer();

observer.add("render homepage", () => {
    let { params, page, limit } = parseURL();

    fetch("/students?" + params.toString())
        .then((res) => res.json())
        .then((data) => {
            render(data);
            pagination(data);
        });
    });
        
observer.add("render student", renderStudent);

export default observer;
