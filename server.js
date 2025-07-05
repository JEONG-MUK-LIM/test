const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');

const app = express(); // express   

//미들웨어
app.use(express.json()); // 클라가 전송한 json을 자바스크립트 객체로 변환
app.use(express.urlencoded({extended:true})); 
// 클라가 전송한 폼데이터를 자바스크립트 객체로 변환, 중첩된 객체표현을 가능하게함
app.use(session({
    secret: 'mySecret', // 세선 암호화 키
    resave: false,      // 요청이 들어왔을 때, 세션변화가 없다면 다시 저장 x
    saveUninitialized:true,  //아무 데이터가 없더라도 세션을 저장
})); //사용자별로 세션데이터를 관리
app.use(express.static(path.join(__dirname,'public'))); // public폴더를 정적파일 서비스로 설정


//몽고db에 연결, node.js서버와 동일한컴퓨터에서 접속해야함
mongoose.connect('mongodb://localhost:27017/test');
//유저스키마 정의
const UserSchema = new mongoose.Schema({
    username: String, 
    password: String,
});
const User = mongoose.model('User', UserSchema);

//로그인 폼 페이지 라우터, 라우터는 주소별로 서버가 어떤 동작을 해줄지 결정
//현재 경로내의 public폴더의 login.html을 응답함
app.get('/login',(req, res) =>{
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

//로그인 처리 라우터
app.post('/login', async (req,res) => { // 비동기함수 생성,항상 promise 반환
    const {username, password} = req.body;
    const user = await User.findOne({username}); //await: 이 함수가 끝날 때까지 기다리란 뜻
    //User스키마에서 username인 첫번째 도큐먼트를 찾음 
    if(!user){ 
        return res.send('<script>alert("존재하지 않는 아이디입니다."); history.back();</script>');}
        //브라우저에서 해당코드를 실행하도록 응답을 보냄
    const isValid = await bcrypt.compare(password, user.password);// 해시값에서 솔트추출해서 비밀번호 해싱->비교
    if(!isValid){
        return res.send('<script>alert("비밀번호가 틀렸습니다.");history.back();</script>');
    }
    req.session.userId = user._id; // 세션에 사용자 정보 저장
    res.send('<script>alert("로그인 성공"); location.href="/";</script>');
});

//회원가입 라우터
app.get('/register', (req, res) => {
  res.send(`
    <h2>회원가입</h2>
    <form action="/register" method="post">
      <input type="text" name="username" placeholder="아이디" required>
      <input type="password" name="password" placeholder="비밀번호" required>
      <button type="submit">회원가입</button>
    </form>
    <a href="/login">로그인</a>
  `);
});
app.post('/register', async (req,res)=>{
    const { username, password} = req.body;
    const exist = await User.findOne({username});
    if(exist){
        return res.send('<script>alert("이미 존재하는 아이디입니다.");history.back();</script>');
    }
    const hash = await bcrypt.hash(password, 10); // 실제 비밀번호 대신 해시값 저장
    await new User({username,password:hash}).save();
    res.send('<script>alert("회원가입 성공!");location.href="login";</script>');
});

//로그아웃 라우터
app.get('/logout', (req, res) =>{
    req.session.destroy();
    res.send('<script>alert("로그아웃 되었습니다.");location.href="login";</script>');
});

//메인페이지
app.get('/', (req,res)=>{
    if(!req.session.userId){
        return res.redirect('/login');
    }
    res.send('<h2>로그인 성공! 메인페이지입니다.<br><a href="/logout"로그아웃</a></h2>');
});

app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});