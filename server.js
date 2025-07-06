require('dotenv').config(); // .env사용

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');
const {body, validationResult} = require('express-validator');
const csurf = require('csurf');



const app = express(); 
//미들웨어
app.use(express.json()); // 클라가 전송한 json을 자바스크립트 객체로 변환
app.use(express.urlencoded({extended:true})); 
// 클라가 전송한 폼데이터를 자바스크립트 객체로 변환, 중첩된 객체표현을 가능하게함
app.use(session({
    secret: process.env.SESSION_SECRET, // 세션 암호화 키, 환경변수로 지정
    resave: false,      // 요청이 들어왔을 때, 세션변화가 없다면 다시 저장 x
    saveUninitialized:false,  //아무 데이터가 없으면 세션을 저장 X
    cookie:{
        httpOnly: true, // 쿠키에 접근금지
        secure: process.env.NODE_ENV === 'production', // 운영환경에서만 활성화, 값과타입이 모두같은지체크
        sameSite: 'lax', // CSRF 공격방지, CSRF: 인증정보를 이용해 타 사이트에 위조요청
                            // sameSite : 쿠키를 언제 전송할지 제어, Strict: 같은사이트에서 온 요청만
                                                             //  lax: GET방식에서만
                                                             //  None: 제한 x, secure=true일때만

        maxAge: 1000 * 60 * 60
    }
})); //사용자별로 세션데이터를 관리

app.use(csurf()); //CSRF방지 미들웨어

app.use(express.static(path.join(__dirname, 'public'))); // public폴더를 정적으로 제공

//몽고db에 연결, node.js서버와 동일한컴퓨터에서 접속해야함
mongoose.connect(process.env.DB_URL)
.then(()=> console.log('DB connected'))
.catch(err => console.error(err));

//유저스키마 정의
const UserSchema = new mongoose.Schema({
    username: String, 
    password: String,
});
const User = mongoose.model('User', UserSchema);




//로그인 폼 페이지 라우터, 라우터는 주소별로 서버가 어떤 동작을 해줄지 결정
//csrf사용시 정적파일을 제공시 csrf토큰을 서버가 줄 수 없으므로 서버에서 직접렌더링
app.get('/login', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>로그인</title>
        <link rel="stylesheet" href="/login.css">
      </head>
      <body>
        <div class="center-wrapper">
          <div class="login-container">
            <h2>로그인</h2>
            <form action="/login" method="post">
              <input type="hidden" name="_csrf" value="${req.csrfToken()}">
              <div class="input-row">
                <input type="text" id="username" name="username" required placeholder="아이디">
              </div>
              <div class="input-row">
                <input type="password" id="password" name="password" required placeholder="비밀번호">
              </div>
              <button type="submit" class="login-btn">로그인</button>
            </form>
            <div class="actions">
              <a href="/register">회원가입</a>
              <span>|</span>
              <a href="/find-id">아이디 찾기</a>
              <span>|</span>
              <a href="/find-password">비밀번호 찾기</a>
            </div>
          </div>
        </div>
      </body>
      </html>
    `);
});

//로그인 처리 라우터
app.post('/login', [
    body('username').isLength({ min:5, max: 20}).trim().escape(), // 좌우공백제거, 특수문자를 16진수문자로 바꿔서 xss방지
    body('password').isLength({ min:6})
    .withMessage('비밀번호는 6자이상이어야 합니다.')
    .not().matches(/\s/)
    .withMessage('비밀번호에 공백이 포함될 수 없습니다.') 
],  async (req,res) => { // 비동기함수 생성,항상 promise 반환
    const errors = validationResult(req);   
    if(!errors.isEmpty()){
        return res.send(`<script>alert("${errors.array()[0].msg}");history.back();</script>`);   
    }
    const {username, password} = req.body;
    const user = await User.findOne({username}); //await: 이 함수가 끝날 때까지 기다리란 뜻
    //User스키마에서 username인 첫번째 도큐먼트를 찾음 
    let isValid = false;
    if(user){
        isValid = await bcrypt.compare(password, user.password); // 해시값에서 솔트추출해서 비밀번호 해싱->비교
    }
    if(!user || !isValid){
        return res.send('<script>alert("아이디 또는 비밀번호가 틀렸습니다.");history.back();</script>');
    }
    req.session.regenerate(function(err){ // 세션 재발급
        if(err) return res.send('<script>alert("세션 오류");history.back();</script>');
        req.session.userId = user._id;      // 세션에 사용자의 식별자 저장
        res.send('<script>alert("로그인 성공"); location.href="/";</script>');
    });
});



//회원가입 폼
app.get('/register', (req, res) => {
    res.send(`
    <h2>회원가입</h2>
    <form action="/register" method="post">
      <input type="hidden" name="_csrf" value="${req.csrfToken()}"> 
      <!-- 서버에서 생성한 CSRF토큰을 검사 -->
      <input type="text" name="username" placeholder="아이디" required>
      <input type="password" name="password" placeholder="비밀번호" required>
      <button type="submit">회원가입</button>
    </form>
    <a href="/login">로그인</a>
  `);
});

//회원가입 처리
app.post('/register', [
    body('username').isLength({min:5, max:20}).trim().escape(),
    body('password').isLength({ min:6}).withMessage('비밀번호는 6자이상이어야 합니다.')
    .not().matches(/\s/).withMessage('비밀번호에 공백이 포함될 수 없습니다.') 
],  async (req,res)=>{
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.send(`<script>alert("${errors.array()[0].msg}");history.back();</script>`);
    }
    const { username, password} = req.body;
    const exist = await User.findOne({username});
    if(exist){
        return res.send('<script>alert("이미 존재하는 아이디입니다.");history.back();</script>');
    }
    const hash = await bcrypt.hash(password, 10); // 실제 비밀번호 대신 해시값 저장
    await new User({username,password:hash}).save(); //유저스키마에 저장
    res.send('<script>alert("회원가입 성공!");location.href="/login";</script>');
});

//로그아웃 라우터
app.get('/logout', (req, res) =>{
    req.session.destroy(function(err){
        res.clearCookie('connect.sid');     //connect.sid:express-session 미들웨어의 세션식별자를 저장
        res.send('<script>alert("로그아웃 되었습니다.");location.href="/login";</script>');
    });
});

//메인페이지
app.get('/', (req,res)=>{           // 메인페이지로의 요청이 들어오면 해당함수 실행
    if(!req.session.userId){        // 세션에 로그인하지 않은 상태라면 
        return res.redirect('/login');    // login페이지로 이동시킴
    }
    res.send('<h2>로그인 성공! 메인페이지입니다.<br><a href="/logout">로그아웃</a></h2>');
});



app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
}); 