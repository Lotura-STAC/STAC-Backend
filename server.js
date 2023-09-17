require("dotenv").config();
const dbsettings = require('./var.js');
const mysql = require('mysql');
const http = require("http");
const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const fcm = require('firebase-admin')
const fs = require('fs');
const cors = require('cors');
const moment = require("moment");
require('console-stamp')(console, 'yyyy/mm/dd HH:MM:ss.l');
const app = express();
app.use(cors());
const server = http.createServer(app);
const http_port = 80;
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
const io = require('socket.io')(server, { cors: { origin: "*" } });
const android = io.of('/app');
const serAccount = require('./firebase_token.json');

fcm.initializeApp({
    credential: fcm.credential.cert(serAccount),
});

const connection = mysql.createConnection({
    host: dbsettings.host,
    user: dbsettings.user,
    password: dbsettings.pw,
    database: dbsettings.db
});

// AccessToken 생성
const generateAccessToken = (id) => {
    return jwt.sign({ id }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "3 days",
    });
};

// RefreshToken 생성
const generateRefreshToken = (id) => {
    return jwt.sign({ id }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: "180 days",
    });
};

// 회원가입 API
app.post("/sign", (req, res) => {
    let admin_id = req.body.admin_id;
    let admin_pw = req.body.admin_pw;
    let guest_id = req.body.guest_id;
    let guest_pw = req.body.guest_pw;
    if ((admin_id == '' || admin_id == null || admin_id == undefined || guest_id == '' || guest_id == null || guest_id == undefined) && (admin_pw == '' || admin_pw == null || admin_pw == undefined || guest_pw == '' || guest_pw == null || guest_pw == undefined)) {
        res.status(500).send('회원가입 실패.');
    } else {
        //DB에 Admin ID 중복되는 값 있는지 확인
        connection.query(`SELECT admin_id FROM user WHERE admin_id = ?;`, [admin_id], function (error, admin_results) {
            let type = new Array();
            if (error) {
                console.log('SELECT id FROM user WHERE id = ? Error');
                console.log(error);
                return;
            }
            //중복이면 return
            if (admin_results.length > 0) {
                res.status(400).send('중복된 Admin ID입니다.');
                return;
            } else {//DB에 Guest ID 중복되는 값 있는지 확인
                connection.query(`SELECT guest_id FROM user WHERE guest_id = ?;`, [guest_id], (insert_error, guest_results) => {
                    if (insert_error) {
                        console.log('SELECT id FROM user WHERE id = ? Error');
                        console.log(error);
                        return;
                    }
                    //중복이면 return
                    if (guest_results.length > 0) {
                        res.status(400).send('중복된 Guest ID입니다.');
                        return;
                    } else {
                        connection.query(`INSERT INTO user (admin_id, admin_pw, guest_id, guest_pw) VALUES (?,?,?,?);`, [admin_id, admin_pw, guest_id, guest_pw], (insert_error, insert_results) => {
                            if (insert_error) {
                                console.log('User Insert Error');
                                console.log(insert_error);
                                res.sendStatus(500);
                                return;
                            }
                            //console.log(insert_results);
                            res.sendStatus(200);
                        });
                    }
                });
            }
        });
    }
});

// 로그인 API
app.post("/login", (req, res) => {
    let id = req.body.id;
    let pw = req.body.pw;
    if ((id == '' || id == null || id == undefined) && (pw == '' || pw == null || pw == undefined)) {
        return res.status(500).send('로그인 실패.');
    } else {
        connection.query(`SELECT admin_id FROM user WHERE admin_id = ? AND admin_pw = ?;`, [id, pw], function (error, admin_results) {
            if (error) {
                console.log('no matching user blyat');
                console.log(error);
                return res.status(500).send('로그인 실패.');
            }
            //console.log(admin_results);
            if (admin_results.length < 1) {
                connection.query(`SELECT guest_id FROM user WHERE guest_id = ? AND guest_pw = ?;`, [id, pw], function (error, guest_results) {
                    if (error) {
                        console.log('no matching user blyat');
                        console.log(error);
                        return res.status(500).send('로그인 실패.');
                    }
                    //console.log(guest_results);
                    if (guest_results.length < 1) {
                        res.status(500).send('비밀번호 오류입니다.')
                    }
                    else {
                        //JWT 토큰 발급-게스트
                        let accessToken = generateAccessToken(guest_results[0].guest_id);
                        let refreshToken = generateRefreshToken(guest_results[0].guest_id);
                        res.json({ accessToken, refreshToken, "role": "guest" });
                    }
                });
            } else {
                //JWT 토큰 발급-어드민
                let accessToken = generateAccessToken(admin_results[0].admin_id);
                let refreshToken = generateRefreshToken(admin_results[0].admin_id);
                res.json({ accessToken, refreshToken, "role": "admin" });
            }
        });
    }
});

// JWT 토큰 유효성 검사
const authenticateAccessToken = (req, res, next) => {
    let authHeader = req.headers["authorization"];
    let token = authHeader && authHeader.split(" ")[1];
    if (!token) {
        console.log("Wrong Token Format");
        return res.sendStatus(401);
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

// JWT 토큰 재발급 API
app.post("/refresh", (req, res) => {
    let refreshToken = req.body.refreshToken;
    if (!refreshToken) return res.sendStatus(401);
    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        (error, user) => {
            if (error) return res.sendStatus(403);
            const accessToken = generateAccessToken(user.id);
            connection.query(`SELECT admin_id FROM user WHERE admin_id = ?;`, [user.id], function (error, a_results) {
                if (a_results.length > 0) {
                    res.json({ accessToken, refreshToken, "role": "admin" });
                    return;
                } else {
                    connection.query(`SELECT guest_id FROM user WHERE guest_id = ?;`, [user.id], function (error, g_results) {
                        if (g_results.length > 0) {
                            res.json({ accessToken, refreshToken, "role": "guest" });
                            return;
                        } else {
                            res.json({ accessToken, refreshToken });
                        }
                    });
                }
            });
        }
    );
});

// 장치 추가 API
app.post("/add_device", authenticateAccessToken, (req, res) => {
    let name = req.body.name;
    let device_no = req.body.device_no;
    let device_type = req.body.device_type;
    connection.query(`SELECT device_no FROM device_data WHERE device_no = ?;`, [device_no], function (error, results) {
        if (results.length > 0) {
            res.status(400).send('이미 추가된 장치입니다.');
            return;
        } else {
            connection.query(`SELECT guest_id FROM user WHERE admin_id = ?;`, [req.user.id], function (error, guestid_results) {
                connection.query(`INSERT INTO device_data (user_id, guest_id, name, device_no, device_type, curr_status, x_pos, y_pos) VALUES (?, ?, ?, ?, ?, ?, ? ,?);`, [req.user.id, guestid_results[0].guest_id, name, device_no, device_type, "0", "0", "0"], (error, results) => {
                    if (error) {
                        console.log('INSERT INTO device_data error:');
                        //console.log(error);
                        res.status(400).send('장치 추가 실패');
                        return;
                    }
                    //console.log(guestid_results);
                    console.log('Device Added-' + name + ',' + device_no + ',' + device_type)
                    res.status(200).send('장치 추가 성공');
                });
            });
        }
    });
});

// 장치 제거 API
app.post("/remove_device", authenticateAccessToken, (req, res) => {
    let device_no = req.body.device_no;
    connection.query(`DELETE FROM device_data WHERE user_id = ? AND device_no = ?;`, [req.user.id, device_no], (error, results) => {
        if (error) {
            console.log('DELETE FROM device_data error:');
            //console.log(error);
            res.status(400).send('장치 제거 실패');
            return;
        }
        console.log('Device Removed-' + device_no)
        res.status(200).send('장치 제거 성공');
    });
});

// 장치 이름 변경 API
app.post("/rename_device", authenticateAccessToken, (req, res) => {
    let device_no = req.body.device_no;
    let new_name = req.body.new_name;
    connection.query(`UPDATE device_data SET name = ? WHERE device_no = ?;`, [new_name, device_no], (error, results) => {
        if (error) {
            console.log('device_data Update query error:');
            //console.log(error);
            res.status(400).send('장치 이름 변경 실패');
            return;
        }
        console.log('Device Name Changed-' + device_no + ',' + new_name);
        res.status(200).send('장치 이름 변경 성공');
    });
});

// 장치 위치 변경 API
app.post("/move_device", authenticateAccessToken, (req, res) => {
    let device_no = req.body.device_no;
    let x_pos_new = req.body.x_pos;
    let y_pos_new = req.body.y_pos;
    connection.query(`UPDATE device_data SET x_pos = ?, y_pos = ? WHERE device_no = ?;`, [x_pos_new, y_pos_new, device_no], (error, results) => {
        if (error) {
            console.log('device_data Update query error:');
            //console.log(error);
            res.status(400).send('장치 위치 변경 실패');
            return;
        }
        console.log('Device Moved-' + device_no + ',' + x_pos_new + ',' + y_pos_new);
        res.status(200).send('장치 위치 변경 성공');
    });
});

//알림 신청 API 
app.post("/notify_me", authenticateAccessToken, (req, res) => {
    let deviceToken = req.body.deviceToken;
    let device_no = req.body.device_no;
    connection.query(`SELECT Token FROM PushAlert WHERE device_id = ? AND expect_status = ? AND Token = ?;`, [device_no, "1", deviceToken], function (error, results) {
        let type = new Array();
        if (error) {
            console.log('SELECT Token query error:');
            console.log(error);
            return;
        }
        //중복이면 return
        if (results.length > 0) {
            console.log('This is a duplicate value');
            res.status(400).send('중복된 신청입니다');
            return;
        } else {
            connection.query(`INSERT INTO PushAlert (Token, device_id, expect_status) VALUES (?, ?, ?);`, [deviceToken, device_no, "1"], (error, results) => {
                if (error) {
                    console.log('deviceStatus Update query error:');
                    //console.log(error);
                    res.status(400).send('알림 신청 실패');
                    return;
                }
                //console.log(results);
                console.log('Push Request Success')
                res.status(200).send('알림 신청 성공');
            });
        }
    });
});

//어드민 알림 신청 API 
app.post("/notify_me_admin", authenticateAccessToken, (req, res) => {
    let deviceToken = req.body.deviceToken;
    connection.query(`SELECT Token FROM PushAlert_Admin WHERE Token = ?;`, [deviceToken], function (error, results) {
        let type = new Array();
        if (error) {
            console.log('SELECT Token query error:');
            console.log(error);
            return;
        }
        //중복이면 return
        if (results.length > 0) {
            console.log('This is a duplicate value');
            res.status(400).send('중복된 신청입니다');
            return;
        } else {
            connection.query(`INSERT INTO PushAlert_Admin (admin_id, Token) VALUES (?, ?);`, [req.user.id, deviceToken], (error, results) => {
                if (error) {
                    console.log('deviceStatus Update query error:');
                    //console.log(error);
                    res.status(400).send('알림 신청 실패');
                    return;
                }
                //console.log(results);
                console.log('Push Request Success')
                res.status(200).send('알림 신청 성공');
            });
        }
    });
});

//어드민 알림 제거 API 
app.post("/no_notify_admin", authenticateAccessToken, (req, res) => {
    connection.query(`DELETE FROM PushAlert_Admin WHERE admin_id = ?;`, [req.user.id], function (error, results) {
        if (error) {
            console.log('DELETE FROM PushAlert_Admin error:');
            console.log(error);
            res.status(200).send('알림 제거 실패');
            return;
        }
        res.status(200).send('알림 제거 성공');
    });
});

//FCM 테스트 코드
app.post("/notify_test", authenticateAccessToken, (req, res) => {
    let deviceToken = req.body.deviceToken;
    let target_tokens = new Array();
    target_tokens[0] = deviceToken;
    let message = {
        notification: {
            title: '인간실격',
            body: `부끄럼 많은 삶을 살았습니다.`,
        },
        tokens: target_tokens,
        android: {
            priority: "high"
        },
        apns: {
            payload: {
                aps: {
                    contentAvailable: true,
                }
            }
        }
    }
    //FCM 메시지 보내기
    fcm.messaging().sendMulticast(message)
        .then((response) => {
            if (response.failureCount > 0) {
                const failedTokens = [];
                response.responses.forEach((resp, idx) => {
                    if (!resp.success) {
                        failedTokens.push(target_tokens[idx]);
                    }
                });
                console.log('List of tokens that caused failures: ' + failedTokens);
            }
            console.log('FCM Success')
            return
        });
});

//권한 확인 API 
app.post("/whoami", authenticateAccessToken, (req, res) => {
    connection.query(`SELECT admin_id FROM user WHERE admin_id = ?;`, [req.user.id], function (error, admin_results) {
        if (error) {
            console.log('no matching user blyat');
            console.log(error);
            return res.status(500).send('로그인 실패.');
        }
        //console.log(admin_results);
        if (admin_results.length < 1) {
            connection.query(`SELECT guest_id FROM user WHERE guest_id = ?;`, [req.user.id], function (error, guest_results) {
                if (error) {
                    console.log('no matching user blyat');
                    console.log(error);
                    return res.status(500).send('로그인 실패.');
                }
                //console.log(guest_results);
                if (guest_results.length < 1) {
                    res.status(500).send('ID 오류입니다.')
                }
                else {
                    res.json({ "role": "guest" });
                }
            });
        } else {
            res.json({ "role": "admin" });
        }
    });
});

//임베디드 Gateway 연결 Socket
io.on('connection', socket => {
    console.log('Socket.IO Gateway Connected:', socket.id)
    socket.on('device_update', request_data => {
        const { device_no, curr_status } = request_data;
        console.log(device_no);
        console.log(curr_status);
        connection.query(`SELECT * FROM device_data WHERE device_no = ?;`, [device_no], function (error, device_data_results) {
            if (error) {
                console.log('UPDATE device_data device_data error');
                console.log(error);
                return;
            }
            //console.log(device_data_results);
            if (device_data_results.length >= 1) {
                connection.query(`UPDATE device_data SET curr_status = ? WHERE device_no = ?;`, [curr_status, device_no], function (error, results) {
                    if (error) {
                        console.log('UPDATE device_data device_data error');
                        console.log(error);
                        return;
                    }
                    //console.log(results);
                });
                if (curr_status == 0)//ON
                {
                    connection.query(`UPDATE device_data SET ON_time = ? WHERE device_no = ?;`, [moment().format(), device_no], (error, results) => {
                        if (error) {
                            console.log('deviceStatus Update query error:');
                            console.log(error);
                            return;
                        }
                        //console.log(results);
                    });
                } else {//OFF
                    connection.query(`UPDATE device_data SET OFF_time = ? WHERE device_no = ?;`, [moment().format(), device_no], (error, results) => {
                        if (error) {
                            console.log('deviceStatus Update query error:');
                            console.log(error);
                            return;
                        }
                        //console.log(results);
                    });
                }
                //console.log(results);
                connection.query(`SELECT user_id, guest_id FROM device_data WHERE device_no = ?;`, [device_no], function (error, results) {
                    if (error) {
                        console.log(error);
                    }
                    connection.query(`SELECT socket_id FROM user_socketid WHERE user_id = ? OR user_id = ?;`, [results[0].user_id, results[0].guest_id], function (error, socket_id_results) {
                        if (error) {
                            console.log(error);
                        }
                        connection.query(`SELECT * FROM device_data WHERE user_id = ? OR guest_id = ?;`, [results[0].user_id, results[0].guest_id], function (error, device_results) {
                            if (error) {
                                console.log('SELECT * FROM device_data error');
                                console.log(error);
                                return;
                            }
                            for (let i = 0; i < socket_id_results.length; i++) {
                                android.to(socket_id_results[i].socket_id).emit('update', device_results);
                            }
                        });
                    });
                });
                //FCM 메시지 전송
                connection.query(`SELECT Token FROM PushAlert WHERE device_id = ? AND expect_status = ?;`, [device_no, curr_status], function (error, token_results) {
                    if (error) {
                        console.log('SELECT Token FROM PushAlert error');
                        console.log(error);
                        return;
                    }
                    connection.query(`SELECT user_id FROM device_data WHERE device_no = ?;`, [device_no], function (error, user_id_results) {
                        if (error) {
                            console.log('SELECT user_id FROM device_data error');
                            console.log(error);
                            return;
                        }
                        connection.query(`SELECT Token FROM PushAlert_Admin WHERE admin_id = ?;`, [user_id_results[0].user_id], function (error, admin_token_results) {
                            if (error) {
                                console.log('SELECT Token FROM PushAlert_Admin error');
                                console.log(error);
                                return;
                            }
                            let target_tokens = new Array();
                            for (let i = 0; i < token_results.length + admin_token_results.length; i++) {
                                if (i < token_results.length) {
                                    target_tokens[i] = token_results[i].Token;
                                } else {
                                    target_tokens[i] = admin_token_results[i].Token;
                                }
                            }
                            //해당되는 Token이 없다면 return
                            if (target_tokens == 0) {
                                console.log("No notification request");
                                return
                            } else {
                                console.log("Notification request");
                                console.log(target_tokens);
                                connection.query(`SELECT ON_time, OFF_time FROM device_data WHERE device_no = ?;`, [device_no], function (error, results) {
                                    if (error) {
                                        console.log('SELECT Token query error:');
                                        console.log(error);
                                        return;
                                    }
                                    //동작시간 계산
                                    let hour_diff = moment(results[0].OFF_time).diff(results[0].ON_time, 'hours');
                                    let minute_diff = moment(results[0].OFF_time).diff(results[0].ON_time, 'minutes') - (hour_diff * 60);
                                    let second_diff = moment(results[0].OFF_time).diff(results[0].ON_time, 'seconds') - (minute_diff * 60) - (hour_diff * 3600);
                                    connection.query(`SELECT device_type FROM device_data WHERE device_no = ?;`, [device_no], function (error, type_results) {
                                        connection.query(`SELECT name FROM device_data WHERE device_no = ?;`, [device_no], function (error, name_results) {
                                            if (type_results[0].device_type == "WASH") {
                                                //FCM 메시지 내용
                                                let message = {
                                                    notification: {
                                                        title: '세탁기 알림',
                                                        body: `${name_results[0].name}의 동작이 완료되었습니다.\r\n동작시간 : ${hour_diff}시간 ${minute_diff}분 ${second_diff}초`,
                                                    },
                                                    tokens: target_tokens,
                                                    android: {
                                                        priority: "high"
                                                    },
                                                    apns: {
                                                        payload: {
                                                            aps: {
                                                                contentAvailable: true,
                                                            }
                                                        }
                                                    }
                                                }
                                                //FCM 메시지 전송
                                                fcm.messaging().sendMulticast(message)
                                                    .then((response) => {
                                                        if (response.failureCount > 0) {
                                                            const failedTokens = [];
                                                            response.responses.forEach((resp, idx) => {
                                                                if (!resp.success) {
                                                                    failedTokens.push(target_tokens[idx]);
                                                                }
                                                            });
                                                            console.log('List of tokens that caused failures: ' + failedTokens);
                                                        }
                                                        console.log('FCM Success')
                                                        return
                                                    });
                                            } else if (type_results[0].device_type == "DRY") {
                                                //FCM 메시지 내용
                                                let message = {
                                                    notification: {
                                                        title: '건조기 알림',
                                                        body: `${name_results[0].name}의 동작이 완료되었습니다.\r\n동작시간 : ${hour_diff}시간 ${minute_diff}분 ${second_diff}초`,
                                                    },
                                                    tokens: target_tokens,
                                                    android: {
                                                        priority: "high"
                                                    },
                                                    apns: {
                                                        payload: {
                                                            aps: {
                                                                contentAvailable: true,
                                                            }
                                                        }
                                                    }
                                                }
                                                //FCM 메시지 전송
                                                fcm.messaging().sendMulticast(message)
                                                    .then((response) => {
                                                        if (response.failureCount > 0) {
                                                            const failedTokens = [];
                                                            response.responses.forEach((resp, idx) => {
                                                                if (!resp.success) {
                                                                    failedTokens.push(target_tokens[idx]);
                                                                }
                                                            });
                                                            console.log('List of tokens that caused failures: ' + failedTokens);
                                                        }
                                                        console.log('FCM Success')
                                                        return
                                                    });
                                            }
                                        });
                                    });
                                    connection.query(`DELETE FROM PushAlert WHERE device_id = ?;`, [device_no], function (error, results) {
                                        if (error) {
                                            console.log('DELETE FROM PushAlert error:');
                                            console.log(error);
                                            return;
                                        }
                                    });
                                });
                            }
                        });
                    });
                });
            } else {
                console.log("This is Not Added Device")
            }
        });
    });
});

//Application, Frontend 연결 Socket
android.on('connection', socket => {
    console.log('Socket.IO Connected(andriod):', socket.id)
    //Application과 Frontend에 현재 상태 DB 넘기기
    socket.on('request_data_all', request_data => {
        console.log('Request Data Received');
        const { accesstoken } = request_data;
        jwt.verify(accesstoken, process.env.ACCESS_TOKEN_SECRET, (error, user) => {
            if (error) {
                console.log(error);
                res.status(400).send('Token Expired');
                return;
            }
            console.log(user.id);
            connection.query(`INSERT INTO user_socketid (user_id, socket_id) VALUES (?,?);`, [user.id, socket.id], (insert_error, insert_results) => {
                if (insert_error) {
                    console.log(insert_error);
                    return;
                }
                //console.log(insert_results);
                console.log('Socket Login');
                connection.query(`SELECT * FROM device_data WHERE user_id = ? OR guest_id = ?;`, [user.id, user.id], function (error, results) {
                    if (error) {
                        console.log('SELECT * FROM device_data error');
                        console.log(error);
                        return;
                    }
                    //console.log(results);
                    android.to(socket.id).emit('update', results);
                });
            });
        });
    });

    //소켓 연결해제시 연결목록 삭제
    socket.on('disconnect', function () {
        console.log("SOCKETIO disconnect EVENT: ", socket.id, " client disconnect");
        connection.query(`DELETE FROM user_socketid WHERE socket_id = ?;`, [socket.id], (error, results) => {
            if (error) {
                console.log(error);
                return;
            }
            //console.log(results);
            console.log('Socket Disconnected');
        });
    });
});

server.listen(http_port, () => {
    console.log(`Server running on ${http_port}`);
});