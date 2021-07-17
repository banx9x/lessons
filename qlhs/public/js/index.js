import validate from "./validate.js";
import observer from "./observer.js";

observer.notify("render homepage");
window.onpopstate = () => observer.notify("render homepage");

const studentForm = document.getElementById("student");
studentForm.addEventListener("submit", (ev) => {
    ev.preventDefault();

    let data = validate();

    if (data) {
        fetch("/students", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(data),
        })
            .then(() => {
                observer.notify("render homepage");
                studentForm.reset();
                document.getElementById("close").click();
            })
            .catch((e) => console.log(e));
    }
});

const search = document.getElementById("search");
search.addEventListener("search", (ev) => {
    let value = search.value.trim();
    history.pushState(null, null, value ? "?q=" + value : "/");
    observer.notify("render homepage");
});
