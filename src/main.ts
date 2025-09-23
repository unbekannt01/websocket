/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-floating-promises */
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Security headers
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", 'cdnjs.cloudflare.com'],
          styleSrc: ["'self'", "'unsafe-inline'"],
          connectSrc: ["'self'", 'ws://localhost:3000', 'wss://localhost:3000'],
          imgSrc: ["'self'", 'data:', 'https:'],
          fontSrc: ["'self'", 'https:', 'data:'],
        },
      },
      crossOriginEmbedderPolicy: false, // Disable for WebSocket compatibility
    }),
  );

  // CORS configuration for local development
  app.enableCors({
    origin: [
      'http://localhost:3000',
      'file://', // For opening HTML file directly
      '*', // Allow all origins for development (remove in production)
    ],
    methods: ['GET', 'POST'],
    credentials: true,
    optionsSuccessStatus: 200,
  });

  const port = 3000;
  console.log(`Server starting on port ${port}`);
  console.log(`Environment: development`);

  await app.listen(port, '0.0.0.0');
  console.log(
    `🔐 Secure WebSocket Chat Backend running on http://localhost:${port}`,
  );
}

bootstrap();
