require("dotenv").config();
const dbsettings = require('./var.js');
const mysql = require('mysql');
const http = require("http");
const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const fcm = require('firebase-admin')
const fs = require('fs');
//const { request } = require("../session-practice/db");

require('console-stamp')(console, 'yyyy/mm/dd HH:MM:ss.l');

//const options = {
//    key: fs.readFileSync('./localhost-key.pem'),
//    cert: fs.readFileSync('./localhost.pem')
//};

const app = express();
const server = http.createServer(app);

const http_port = 80;
const https_port = 443;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

//const https = require('https').createServer(options, app);
const io = require('socket.io')(server, { cors: { origin: "*" } })
const android = io.of('/app');

const connection = mysql.createConnection({
    host: dbsettings.host,
    user: dbsettings.user,
    password: dbsettings.pw,
    database: dbsettings.db
});


// access token을 secret key 기반으로 생성
const generateAccessToken = (id) => {
    return jwt.sign({ id }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "15m",
    });
};

// refersh token을 secret key  기반으로 생성
const generateRefreshToken = (id) => {
    return jwt.sign({ id }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: "180 days",
    });
};

// 회원가입 DB에 저장
app.post("/sign", (req, res) => {
    let id = req.body.id;
    let pw = req.body.pw;

    //DB에 중복되는 값 있는지 확인
    connection.query(`SELECT id FROM user WHERE id = ?;`, [id], function (error, results) {
        let type = new Array();
        if (error) {
            console.log('SELECT id FROM user WHERE id = ? Error');
            console.log(error);
            return;
        }
        //중복이면 return
        if (results.length > 0) {
            res.status(400).send('중복된 ID입니다.');
            return;
        } else {//중복 아니면 DB에 ID,PW등록
            connection.query(`INSERT INTO user (id, pw) VALUES (?,?);`, [id, pw], (insert_error, insert_results) => {
                if (insert_error) {
                    console.log('User Insert Error');
                    console.log(insert_error);
                    res.sendStatus(500);
                    return;
                }
                console.log(insert_results);
                res.sendStatus(200);
            });
        }
    });
});


// login 요청 및 성공시 access token, refresh token 발급
app.post("/login", (req, res) => {
    let id = req.body.id;
    let pw = req.body.pw;

    connection.query(`SELECT id FROM user WHERE id = ? AND pw = ?;`, [id, pw], function (error, results) {
        if (error) {
            console.log('no matching user blyat');
            console.log(error);
            return res.status(500).send('로그인 실패.');
        }
        console.log(results);
        if (results.length < 1) {
            res.status(500).send('비밀번호 오류입니다.')
        }
        else {
            let accessToken = generateAccessToken(results[0].id);
            let refreshToken = generateRefreshToken(results[0].id);
            res.json({ accessToken, refreshToken });
        }

    });
});

// access token의 유효성 검사
const authenticateAccessToken = (req, res, next) => {
    let authHeader = req.headers["authorization"];
    let token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        console.log("wrong token format or token is not sended");
        return res.sendStatus(400);
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
        if (error) {
            console.log(error);
            return res.sendStatus(403);
        }

        req.user = user;
        next();
    });
};

// access token을 refresh token 기반으로 재발급
app.post("/refresh", (req, res) => {
    let refreshToken = req.body.refreshToken;
    if (!refreshToken) return res.sendStatus(401);

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (error, user) => {
            if (error) return res.sendStatus(403);

            const accessToken = generateAccessToken(user.id);

            res.json({ accessToken,refreshToken });
        }
    );
});

// access token 유효성 확인을 위한 예시 요청
app.get("/user", authenticateAccessToken, (req, res) => {
    console.log(req.user);
    res.sendStatus(200);
});

android.on('connection', socket => {
    console.log('Socket.IO Connected(andriod):', socket.id)
    socket.on('Socket_login', login_data => {
        const { accesstoken, user_id } = login_data;
        jwt.verify(accesstoken, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
            if (error) {
                console.log(error);
            }
            console.log(user_id);
            console.log(",");
            console.log(user);
            if (user.id == user_id) {
                connection.query(`INSERT INTO user_socketid (user_id, socket_id) VALUES (?,?);`, [user_id, socket.id], (insert_error, insert_results) => {
                    if (insert_error) {
                        console.log(insert_error);
                        return;
                    }
                    console.log(insert_results);
                });
            }
        });
    })
    socket.on('request_data_all', request_data => {
        const { user_id, accesstoken } = request_data;
        //Application과 Frontend에 현재 상태 DB 넘기기
        jwt.verify(accesstoken, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
            if (error) {
                console.log(error);
            }
            console.log(user_id);
            console.log(",");
            console.log(user);
            if (user.id == user_id) {
                connection.query(`SELECT * FROM device_data WHERE user_id = ?;`, [user_id], function (error, results) {
                    if (error) {
                        console.log('SELECT * FROM device_data error');
                        console.log(error);
                        return;
                    }
                    console.log(results);
                    android.emit('update', results)
                });
            }
        });
    })
    socket.on('Add_Device', request_data => {
        const { user_id, accesstoken, device_no, device_type } = request_data;
        jwt.verify(accesstoken, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
            if (error) {
                console.log(error);
            }
            console.log(user_id);
            console.log(",");
            console.log(user);
            if (user.id == user_id) {
                connection.query(`INSERT INTO device_data (user_id, device_no, device_type, curr_status) VALUES (?, ?, ?, ?);`, [user_id, device_no, device_type, "0"], (error, results) => {
                    if (error) {
                        console.log('INSERT INTO device_data error:');
                        console.log(error);
                        return;
                    }
                    console.log(results);
                    console.log('device_data insert Success')
                });
            }
        });
    })
    socket.on('Remove_Device', request_data => {
        const { user_id, accesstoken, device_no } = request_data;
        jwt.verify(accesstoken, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
            if (error) {
                console.log(error);
            }
            console.log(user_id);
            console.log(",");
            console.log(user);
            if (user.id == user_id) {
                connection.query(`DELETE FROM device_data WHERE user_id = ? AND device_no = ?;`, [user_id, device_no], (error, results) => {
                    if (error) {
                        console.log('DELETE FROM device_data error:');
                        console.log(error);
                        return;
                    }
                    console.log(results);
                    console.log('device_data delete Success')
                });
            }
        });
    })
    socket.on('disconnect', function () {
        console.log("SOCKETIO disconnect EVENT: ", socket.id, " client disconnect");
        connection.query(`DELETE FROM user_socketid WHERE socket_id = ?;`, [socket.id], (error, results) => {
            if (error) {
                console.log(error);
                return;
            }
            console.log(results);
        });
    })
})

server.listen(http_port, () => {
    console.log(`Server running on ${http_port}`);
});

//https.listen(https_port, () => {
//    console.log(`Listening to port ${https_port}`)
//})
