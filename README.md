# odoo18_line_login
Log in with LINE
  เป็น Module ที่ติดตั้งแล้วจะเชื่อมโยงการ Login (Frontend) โดยผ่าน LINE Log in ปัจจุบันใช้ API 2.1

ก่อนติดตั้ง Module:
  pip instsall pyjwt

LINE Dependency
  1. https://developers.line.biz (ต้องสร้าง Provider, Line Login)
  2. ต้องได้ channel_id และ channel_secret
  3. ต้องรู้ Callback URL ของตัวเอง
