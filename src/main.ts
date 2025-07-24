/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-floating-promises */
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable CORS for all origins (you can restrict this in production)
  app.enableCors({
    origin: '*',
    methods: ['GET', 'POST'],
    credentials: true,
  });

  const port = process.env.PORT || 3000;
  console.log(`Server starting on port ${port}`);

  await app.listen(port, '0.0.0.0');
  console.log(`WebSocket Chat Backend running on port ${port}`);
}
bootstrap();
