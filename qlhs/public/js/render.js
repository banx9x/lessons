import { parseURL } from "./utils.js";

const tbody = document.querySelector(".data");

export default function (students) {
    let { page, limit } = parseURL();

    let html = students.slice((page - 1) * limit, page * limit).map((s) => {
        return `
            <tr>
                <td>${s.id}</td>
                <td>${s.first_name}</td>
                <td>${s.last_name}</td>
                <td>
                    <a href="mailto:${s.email}">
                        ${s.email}
                    </a>
                </td>
                <td>
                    <a href="tel:${s.phone}">
                        ${s.phone}
                    </a>
                </td>
                <td>
                    <a href="student.html?sid=${s.id}">
                        <i class="bi bi-info-circle"></i>
                    </a>
                </td>
            </tr>
        `;
    });

    tbody.innerHTML = html.join("");
}

export function renderStudent({ first_name, last_name, email, phone }) {
    let html = `
            <p>Họ: ${last_name}</p>
            <p>Tên: ${first_name}</p>
            <p>Email: ${email}</p>
            <p>Phone: ${phone}</p>
        `;

    document.title = first_name + " " + last_name;
    document.getElementById("info").innerHTML = html;
}
