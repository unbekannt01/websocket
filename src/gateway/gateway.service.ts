/* eslint-disable prettier/prettier */
import {
  ConnectedSocket,
  MessageBody,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
} from '@nestjs/websockets';
import { Socket } from 'socket.io';

@WebSocketGateway({
  cors: {
    origin: '*',
  },
})
export class GatewayService {
  @WebSocketServer()
  socket: Socket;

  handleConnection(client: Socket) {
    console.log('User Connected...!', client.id);

    client.broadcast.emit('user-joined', {
      message: `User Joined the chat: ${client.id}`,
    });
  }

  handleDisconnect(client: Socket) {
    console.log('User Disconnected...!', client.id);

    client.broadcast.emit('user-left', {
      message: `User Left from the chat: ${client.id}`,
    });
  }

  @SubscribeMessage('message')
  handleMessage(@MessageBody() body: any, @ConnectedSocket() client: Socket) {
    console.log(body);
    console.log('Connected... client: ' + client.id);

    this.socket.except(client.id).emit('message', body);
  }
}
