import { Request, Response } from "express";
import { exec } from "child_process";
import * as crypto from "crypto";

interface Order { id: number; ref: string; }

export function getOrder(req: Request, res: Response, db: any): void {
  const ref: string = req.query.ref as string;
  db.query(`SELECT * FROM orders WHERE ref = '${ref}'`);
}

export function ping(req: Request, res: Response): void {
  const host: string = req.query.host as string;
  exec("ping -c 1 " + host, (err: Error | null, out: string) => res.send(out));
}

export function calc(req: Request, res: Response): void {
  res.send(String(eval(req.body.expr as string)));
}

export function token(user: string): string {
  return crypto.createHash("sha1").update(user).digest("hex");
}

export function safeOrder(req: Request, db: any): Promise<Order[]> {
  return db.query("SELECT * FROM orders WHERE ref = ?", [req.query.ref]);
}
