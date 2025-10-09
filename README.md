# Secure WebSocket Chat Backend

A real-time chat application backend built with NestJS and Socket.IO.

## Features

- Password-protected chat rooms
- Real-time messaging
- Rate limiting and security protection
- Session management
- Automatic room cleanup

## Quick Start

1. **Install dependencies**
```bash
npm install
```

2. **Start the server**
```bash
npm run start:dev
```

Server runs on `http://localhost:3000`

## WebSocket Events

### Create Room
```javascript
socket.emit('create-room', {
  roomName: 'My Room',
  password: 'MyPassword123'
});
```

### Join Room
```javascript
socket.emit('join-room', {
  roomId: 'ABC12345',
  password: 'MyPassword123'
  // OR use inviteToken instead of password
});
```

### Send Message
```javascript
socket.emit('room-message', {
  roomId: 'ABC12345',
  username: 'John',
  text: 'Hello everyone!',
  timestamp: new Date().toISOString()
});
```

### Leave Room
```javascript
socket.emit('leave-room', {
  roomId: 'ABC12345'
});
```

## Rate Limits

- Create room: 3 per 5 minutes
- Join room: 10 per minute  
- Send message: 30 per minute
- Connections: 5 per minute

## Environment Variables

```env
NODE_ENV=development
ALLOWED_ORIGINS=https://yourdomain.com
PORT=3000
```

## Production

1. Set `NODE_ENV=production`
2. Configure `ALLOWED_ORIGINS` 
3. Run `npm run build && npm run start:prod`

That's it! 🚀
