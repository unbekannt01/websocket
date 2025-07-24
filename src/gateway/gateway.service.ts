/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-floating-promises */
/* eslint-disable prettier/prettier */
import {
  ConnectedSocket,
  MessageBody,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';

interface Room {
  id: string;
  name: string;
  password: string;
  creator: string;
  members: Set<string>;
  createdAt: Date;
}

interface User {
  id: string;
  username?: string;
  currentRoom?: string;
}

@WebSocketGateway({
  cors: {
    origin: '*',
  },
})
export class GatewayService {
  @WebSocketServer()
  server: Server;

  private rooms: Map<string, Room> = new Map();
  private users: Map<string, User> = new Map();

  handleConnection(client: Socket) {
    console.log('User Connected...!', client.id);

    // Initialize user
    this.users.set(client.id, {
      id: client.id,
    });
  }

  handleDisconnect(client: Socket) {
    console.log('User Disconnected...!', client.id);

    const user = this.users.get(client.id);
    if (user && user.currentRoom) {
      this.leaveRoom(client, user.currentRoom);
    }

    this.users.delete(client.id);
  }

  @SubscribeMessage('create-room')
  handleCreateRoom(
    @MessageBody() data: { roomName: string; password: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      const { roomName, password } = data;

      // Validate input
      if (!roomName || !password) {
        client.emit('room-error', {
          message: 'Room name and password are required',
        });
        return;
      }

      if (roomName.length < 3) {
        client.emit('room-error', {
          message: 'Room name must be at least 3 characters',
        });
        return;
      }

      if (password.length < 4) {
        client.emit('room-error', {
          message: 'Password must be at least 4 characters',
        });
        return;
      }

      // Generate unique room ID
      const roomId = this.generateRoomId();

      // Create room
      const room: Room = {
        id: roomId,
        name: roomName,
        password: password,
        creator: client.id,
        members: new Set([client.id]),
        createdAt: new Date(),
      };

      this.rooms.set(roomId, room);

      // Update user
      const user = this.users.get(client.id);
      if (user) {
        user.currentRoom = roomId;
      }

      // Join socket room
      client.join(roomId);

      console.log(`Room created: ${roomId} by ${client.id}`);

      client.emit('room-created', {
        roomId,
        roomName,
        message: 'Room created successfully',
      });
    } catch (error) {
      console.error('Error creating room:', error);
      client.emit('room-error', { message: 'Failed to create room' });
    }
  }

  @SubscribeMessage('join-room')
  handleJoinRoom(
    @MessageBody() data: { roomId: string; password: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      const { roomId, password } = data;

      // Validate input
      if (!roomId || !password) {
        client.emit('room-error', {
          message: 'Room ID and password are required',
        });
        return;
      }

      // Check if room exists
      const room = this.rooms.get(roomId);
      if (!room) {
        client.emit('room-error', { message: 'Room not found' });
        return;
      }

      // Check password
      if (room.password !== password) {
        client.emit('room-error', { message: 'Invalid password' });
        return;
      }

      // Leave current room if any
      const user = this.users.get(client.id);
      if (user && user.currentRoom) {
        this.leaveRoom(client, user.currentRoom);
      }

      // Join new room
      room.members.add(client.id);
      if (user) {
        user.currentRoom = roomId;
      }

      client.join(roomId);

      console.log(`User ${client.id} joined room: ${roomId}`);

      // Notify user
      client.emit('room-joined', {
        roomId,
        roomName: room.name,
        message: 'Successfully joined room',
      });

      // Notify other room members
      client.to(roomId).emit('user-joined', {
        message: `A user joined the room`,
      });
    } catch (error) {
      console.error('Error joining room:', error);
      client.emit('room-error', { message: 'Failed to join room' });
    }
  }

  @SubscribeMessage('leave-room')
  handleLeaveRoom(
    @MessageBody() data: { roomId: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      const { roomId } = data;
      this.leaveRoom(client, roomId);
    } catch (error) {
      console.error('Error leaving room:', error);
    }
  }

  @SubscribeMessage('room-message')
  handleRoomMessage(
    @MessageBody()
    data: { roomId: string; username: string; text: string; timestamp: string },
    @ConnectedSocket() client: Socket,
  ) {
    try {
      const { roomId, username, text, timestamp } = data;

      // Validate input
      if (!roomId || !username || !text) {
        return;
      }

      // Check if room exists
      const room = this.rooms.get(roomId);
      if (!room) {
        client.emit('room-error', { message: 'Room not found' });
        return;
      }

      // Check if user is member of room
      if (!room.members.has(client.id)) {
        client.emit('room-error', {
          message: 'You are not a member of this room',
        });
        return;
      }

      // Update user's username
      const user = this.users.get(client.id);
      if (user) {
        user.username = username;
      }

      console.log(`Message in room ${roomId} from ${username}: ${text}`);

      // Broadcast message to all room members except sender
      client.to(roomId).emit('room-message', {
        roomId,
        username,
        text,
        timestamp,
      });
    } catch (error) {
      console.error('Error handling room message:', error);
    }
  }

  // Legacy message handler for backward compatibility
  @SubscribeMessage('message')
  handleMessage(@MessageBody() body: any, @ConnectedSocket() client: Socket) {
    console.log('Legacy message received:', body);
    console.log('Connected client:', client.id);

    // Broadcast to all connected clients except sender
    this.server.except(client.id).emit('message', body);
  }

  private leaveRoom(client: Socket, roomId: string) {
    const room = this.rooms.get(roomId);
    if (room) {
      room.members.delete(client.id);
      client.leave(roomId);

      // Update user
      const user = this.users.get(client.id);
      if (user) {
        user.currentRoom = undefined;
      }

      console.log(`User ${client.id} left room: ${roomId}`);

      // Notify other room members
      if (room.members.size > 0) {
        client.to(roomId).emit('user-left', {
          message: `A user left the room`,
        });
      }

      // Clean up empty rooms (except keep for a while in case someone rejoins)
      if (room.members.size === 0) {
        setTimeout(() => {
          const currentRoom = this.rooms.get(roomId);
          if (currentRoom && currentRoom.members.size === 0) {
            this.rooms.delete(roomId);
            console.log(`Cleaned up empty room: ${roomId}`);
          }
        }, 300000); // 5 minutes
      }
    }
  }

  private generateRoomId(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 8; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    // Ensure uniqueness
    if (this.rooms.has(result)) {
      return this.generateRoomId();
    }

    return result;
  }

  // Optional: Add method to get room statistics
  @SubscribeMessage('get-room-info')
  handleGetRoomInfo(
    @MessageBody() data: { roomId: string },
    @ConnectedSocket() client: Socket,
  ) {
    const { roomId } = data;
    const room = this.rooms.get(roomId);

    if (room && room.members.has(client.id)) {
      client.emit('room-info', {
        roomId: room.id,
        roomName: room.name,
        memberCount: room.members.size,
        createdAt: room.createdAt,
      });
    }
  }
}
