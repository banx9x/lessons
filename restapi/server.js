import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import jwt from "jsonwebtoken";
import jsonServer from "json-server";
import cookieParser from "cookie-parser";
import { Low, JSONFile } from "lowdb";
import lodash from "lodash";
import multer from "multer";
const storage = multer.diskStorage({
    destination: (req, file, callback) =>
        callback(null, "public/upload/avatar"),
    filename: (req, file, callback) =>
        callback(
            null,
            req.user.username +
                "-" +
                Date.now() +
                "." +
                file.mimetype.split("/")[1]
        ),
});
const uploadAvatar = multer({
    storage: storage,
    limits: {
        fileSize: 2097152,
        fieldSize: 2097152,
        files: 1,
    },
    fileFilter: (req, file, callback) => {
        if (!["image/png", "image/jpg", "image/jpeg"].includes(file.mimetype)) {
            callback(new multer.MulterError("LIMIT_UNEXPECTED_FILE"));
        } else {
            callback(null, true);
        }
    },
}).single("avatar");

import Joi from "joi";

const file = path.join(__dirname, "db.json");
const adapter = new JSONFile(file);
const db = new Low(adapter);

await db.read();
db.data = db.data || { users: [], todos: [] };
db.chain = lodash.chain(db.data);

const server = jsonServer.create();
const router = jsonServer.router(path.join(__dirname, "db.json"), {
    foreignKeySuffix: "_id",
});
const middlewares = jsonServer.defaults();

server.use(jsonServer.bodyParser);
server.use(cookieParser());
server.use(middlewares);

function isVerify(req, res, next) {
    let token = req.cookies["x-auth-token"];

    if (!token) {
        req.user = null;
        next();
    } else {
        try {
            let decode = jwt.verify(token, "SecretKey");
            console.log(decode);
            req.user = decode;
            next();
        } catch (error) {
            req.user = null;
            next();
        }
    }
}

function isAuth(req, res, next) {
    if (!req.user) {
        res.statusMessage = "Access Denied!!!";
        res.status(401);
        res.send("Access Denied!!!");
        return;
    }

    next();
}

server.get("/", isVerify, (req, res, next) => {
    if (!req.user) {
        res.redirect("/signin");
        return;
    }

    res.setHeader("Content-Type", "text/html; charsets=UTF-8");
    res.sendFile(path.join(__dirname, "public", "home.html"));
});

server.get("/signin", isVerify, (req, res, next) => {
    if (req.user) {
        res.redirect("/");
        return;
    }

    res.setHeader("Content-Type", "text/html; charsets=UTF-8");
    res.sendFile(path.join(__dirname, "public", "signin.html"));
});

server.post("/api/signin", (req, res, next) => {
    let { username, password } = req.body;

    let user = db.chain.get("users").find({ username, password }).value();

    if (user) {
        let token = jwt.sign({ id: user.id }, "SecretKey");
        res.cookie("x-auth-token", token, {
            httpOnly: true,
            expires: new Date().setFullYear(new Date().getFullYear + 1),
        });
        res.cookie("x-auth-token", token, {
            httpOnly: true,
            path: "/",
            expires: new Date(Date.now() + 86400000),
        });
        res.status(301);
        res.setHeader("url", "/");
        res.send("Login Success!!!");
    } else {
        res.status(400).send("User or password incorrect!!!");
    }
});

server.post("/api/signout", (req, res, next) => {
    res.cookie("x-auth-token", "");
    res.status(301);
    res.setHeader("url", "/login");
    res.send("Logout Success!!!");
});

server.post("/api/signup", async (req, res, next) => {
    let schema = Joi.object({
        username: Joi.string()
            .pattern(/^[a-zA-Z][a-zA-Z0-9]{5,19}$/)
            .required()
            .messages({
                any: "Tên đăng nhập phải có độ dài 6 - 20 ký tự và số, không được chứa ký tự đặc biệt, không được bắt đầu bằng một số!!!",
            }),
        password: Joi.string().min(6).max(20).required().messages({
            any: "Mật khẩu phải có độ dài 6 - 20 ký tự!!!",
        }),
    });

    let { value, error } = schema.validate(req.body);

    if (error) {
        res.status(400).send(error.message);
        return;
    }

    let { username, password } = value;

    let user = db.chain.get("users").find({ username }).value();

    if (user) {
        res.statusMessage = "Account already exists!!!";
        res.status(400).send("Account already exists!!!");
    } else {
        let id = Math.max(...db.data.users.map((u) => u.id)) + 1;
        db.data.users.push({ id, username, password });
        await db.write();

        let token = jwt.sign({ id }, "SecretKey");
        res.cookie("x-auth-token", token, {
            httpOnly: true,
            expires: new Date().setFullYear(new Date().getFullYear + 1),
        });

        res.cookie("x-auth-token", token, {
            httpOnly: true,
            path: "/",
            expires: new Date(Date.now() + 86400000),
        });

        res.status(301);
        res.setHeader("url", "/");
        res.send("Signup Success!!!");
    }
});

// fetch("/api/upload", {
//     method: "POST",
//     body: new FormData(form),
// }).then((res) => console.log(res.statusText));

server.post("/api/uploadAvatar", isAuth, (req, res, next) => {
    uploadAvatar(req, res, async (err) => {
        if (!req.file) {
            res.statusMessage = "Please choose an image!!!";
            res.status(400).end();
            return;
        }

        if (err instanceof multer.MulterError) {
            if (err.code === "LIMIT_FILE_SIZE") {
                res.statusMessage =
                    "The image file exceeds the allowed size!!!";
                res.status(400).end();
                return;
            }

            if (err.code === "LIMIT_UNEXPECTED_FILE") {
                res.statusMessage = "Inappropriate image format!!!";
                res.status(400).end();
                return;
            }
        } else if (err) {
            res.statusMessage = "Unexpected Error!!!";
            res.status(500).json(err).end();
        } else {
            let path = req.file.path.replace("public/", "");
            let user = db.chain
                .get("users")
                .find({ id: req.user.id })
                .set("avatar", path)
                .value();
            await db.write();
            res.statusMessage = "Upload success!!!";
            res.status(201).json({ src: user.avatar }).end();
        }
    });
});

server.use("/api", isAuth, router);

server.use((err, req, res) => {
    console.log(err);
});

server.listen(3000, () => {
    console.log("Server is running on http://localhost:3000/");
});
