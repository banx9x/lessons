let todos;
let doing = [];
let completed = [];

let newTodo = document.querySelector(".new-todo");
let todoInput = document.querySelector(".todo-input");

let doingNumber = document.querySelector(".doing .todo-number");
let completedNumber = document.querySelector(".completed .todo-number");

let doingList = document.querySelector(".doing .todo-list");
let completedList = document.querySelector(".completed .todo-list");

let btnMore = document.querySelector(".btn-more");

function xhr(method, url, data, callback) {
    let xhr = new XMLHttpRequest();

    xhr.open(method, url);

    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.responseType = "json";

    xhr.send(typeof data === "object" ? JSON.stringify(data) : data);

    xhr.onerror = function () {
        console.error("Cannot send HTTP Request!!!");
    };

    xhr.onload = function () {
        if (xhr.status >= 200 && xhr.status < 300) callback(xhr.response);
        else console.error("Error: ", xhr.response);
    };
}

function createTodo(todo) {
    let li = document.createElement("li");
    li.className = "todo-item";

    li.innerHTML = todo.completed
        ? `<i class="bi bi-check2"></i> ${todo.title}`
        : `<i class="bi bi-circle"></i> ${todo.title}`;

    if (!todo.completed)
        li.addEventListener(
            "click",
            function () {
                todo.completed = true;
                todo.modified = Date.now();

                doing = doing.filter(function (t) {
                    return t !== todo;
                });

                completed.unshift(todo);

                let node = createTodo(todo);

                xhr("PUT", "/todo/" + todo.id, todo, function () {
                    completedList.prepend(node);
                    completedList.lastElementChild.remove();
                    li.remove();
                });

                updateNumber();
            },
            { once: true }
        );

    return li;
}

function updateNumber() {
    doingNumber.textContent = doing.length;
    completedNumber.textContent = completed.length;

    if (completed.length > 2) {
        btnMore.textContent = `... ${completed.length - 2} công việc khác`;
    }
}

function updateDate() {
    let date = new Date();

    let dateString = date.toLocaleString("vi-VN", {
        weekday: "long",
        day: "2-digit",
        month: "long",
        year: "numeric",
    });

    let saperator = dateString.indexOf(",") + 1;

    document.querySelector(".day").textContent = dateString.slice(0, saperator);
    document.querySelector(".date").textContent = dateString.slice(saperator);
}

updateDate();

function render() {
    updateNumber();

    doing.forEach(function (todo) {
        let node = createTodo(todo);
        doingList.append(node);
    });

    completed.slice(0, 2).forEach(function (todo) {
        let node = createTodo(todo);
        completedList.append(node);
    });
}

xhr("GET", "/todo", null, function (data) {
    todos = data;
    todos.forEach(function (todo) {
        if (todo.completed) completed.push(todo);
        else doing.push(todo);
    });

    completed.sort(function (a, b) {
        return b.modified - a.modified;
    });

    render();
});

document.querySelector(".btn-add").addEventListener("click", function () {
    newTodo.style.display = "block";
    todoInput.focus();
});

document.querySelector(".btn-cancel").addEventListener("click", function () {
    newTodo.style.display = "";
    todoInput.value = "";
});

document.forms.new.addEventListener("submit", function (ev) {
    ev.preventDefault();

    if (todoInput.value.trim().length === 0) {
        alert("Vui lòng nhập nội dung công việc!!!");
    } else {
        let todo = {
            title: todoInput.value.trim(),
            completed: false,
            modified: Date.now(),
        };

        xhr("POST", "/todo", todo, function (data) {
            newTodo.style.display = "";
            todoInput.value = "";
            doing.push(data);
            let node = createTodo(data);
            doingList.append(node);
            updateNumber();
        });
    }
});

btnMore.addEventListener("click", function () {
    if (!btnMore.classList.contains("show")) {
        completed.slice(2).forEach(function (todo) {
            let node = createTodo(todo);
            completedList.append(node);
            btnMore.textContent = "Ẩn bớt";
            btnMore.classList.add("show");
        });
    } else {
        btnMore.classList.remove("show");
        Array.from(completedList.children)
            .slice(2)
            .forEach(function (node) {
                node.remove();
            });
        updateNumber();
    }
});
