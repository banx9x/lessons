import observer from "./observer.js";
import validate from "./validate.js";
import { form, firstname, lastname, email, phone } from "./validate.js";
import { parseURL } from "./utils.js";

let student;

let { params } = parseURL();
let sid = params.get("sid");

fetch("/students/" + sid)
    .then((res) => res.json())
    .then((data) => {
        student = data;
        observer.notify("render student", data);
    })
    .catch((e) => console.log(e));

let btnBack = document.getElementById("back");
btnBack.addEventListener("click", (e) => {
    if (document.referrer) {
        location.href = document.referrer;
    } else {
        location.href = "/";
    }
});

let btnDelete = document.getElementById("delete");
btnDelete.addEventListener("click", (e) => {
    let isConfirm = confirm(`Có chắc muốn xóa ${document.title}???`);

    if (isConfirm) {
        fetch("/students/" + sid, {
            method: "DELETE",
        })
            .then(() => btnBack.click())
            .catch((e) => console.log(e));
    }
});

let modal = document.getElementById("modal");
modal.addEventListener("show.bs.modal", (e) => {
    firstname.value = student.first_name;
    lastname.value = student.last_name;
    email.value = student.email;
    phone.value = student.phone;
});

form.addEventListener("submit", (e) => {
    e.preventDefault();

    let data = validate();

    if (data) {
        fetch("/students/" + sid, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(data),
        })
            .then((r) => r.json())
            .then((data) => {
                student = data;
                observer.notify("render student", data);
                form.reset();
                document.getElementById("close").click();
            });
    }
});
