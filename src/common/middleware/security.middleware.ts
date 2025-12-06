import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import hpp from 'hpp';
import rateLimit from 'express-rate-limit';

@Injectable()
export class SecurityMiddleware implements NestMiddleware {
    private readonly helmetMiddleware: any;
    private readonly hppMiddleware: any;
    private readonly limiterMiddleware: any;

    constructor() {
        this.helmetMiddleware = helmet();
        this.hppMiddleware = hpp();
        this.limiterMiddleware = rateLimit({
            windowMs: 15 * 60 * 1000,
            max: 100, // 100 requests / 15min per IP
        });
    }

    use(req: Request, res: Response, next: NextFunction) {
        this.helmetMiddleware(req, res, (err: any) => {
            if (err) return next(err);
            this.hppMiddleware(req, res, (err2: any) => {
                if (err2) return next(err2);
                this.limiterMiddleware(req, res, next);
            });
        });
    }
}