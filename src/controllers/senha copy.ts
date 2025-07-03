// import { RequestHandler } from "express";
// import z from "zod";
// import * as senha from "../services/senha";
// import { Prioridades, SenhaStatus } from "../generated/prisma";

// export const createSenha: RequestHandler = async (req, res) => {
//   const SenhaSchemaParams = z.object({
//     servicoId: z.string().min(1).max(255),

//     cidadaoId: z.string().min(1).max(255),

//     //status: z.enum(["PENDENTE", "ATENDIDO", "CANCELADO"]),
//   });

//   const SenhaSchemaBody = z.object({
//     prioridade: z.enum([
//       "NAO_PRIORITARIO",
//       "PRIORITARIO",
//       "IDOSO_ACIMA_DE_80_ANOS",
//     ]),
//   });

//   const BodySchema = SenhaSchemaBody.safeParse(req.body);
//   console.log("BodySchema", BodySchema.data);

//   // if (!BodySchema.success) {
//   //   res.status(400).json({ error: "erro  prioridades" });
//   // }

//   const ParamsSchema = SenhaSchemaParams.safeParse(req.params);
//   if (!ParamsSchema.success) {
//     res.status(400).json({ error: "erro ao passar os params" });
//     return;
//   }

//   const newSenha = await senha.createSenha({
//     ...ParamsSchema.data,
//     ...BodySchema.data,
//   });

//   if (!newSenha) {
//     res.status(500).json({ error: "Erro ao criar Senha" });
//     return;
//   }
//   res.status(201).json(newSenha);
//   return;
// };

// // PROXIMA SENHA

// export const chamarProximaSenha: RequestHandler = async (req, res) => {
//   const SenhaSchemaParams = z.object({
//     servicoId: z.string().min(1).max(255),
//     usuarioId: z.string().min(1).max(255),
//     // cidadaoId: z.string().min(1).max(255),
//     reparticaoId: z.string().min(1).max(255),
//     guicheId: z.string().min(1).max(255),
//   });

//   const params = SenhaSchemaParams.safeParse(req.params);
//   if (!params.success) {
//     res.status(400).json({ error: "erro ao passar os params" });
//     return;
//   }

//   const senhaChamada = await senha.chamarProximaSenha({
//     ...params.data,
//   });

//   if (!senhaChamada) {
//     res.status(500).json({ error: "Erro ao chamar a próxima senha" });
//     return;
//   }
//   res.status(200).json(senhaChamada);
// };

// // UPDATE SENHA

// export const updateSenha: RequestHandler = async (req, res) => {
//   const SenhaSchemaParams = z.object({
//     senhaId: z.string(),
//     usuarioId: z.string().min(1).max(255),
//     guicheId: z.string().min(1).max(255),
//   });

//   const SenhaSchemaBody = z.object({
//     status: z.enum(["PENDENTE", "ATENDIDA", "EM_ATENDIMENTO", "CANCELADA"]),
//   });

//   const BodySchema = SenhaSchemaBody.safeParse(req.body);
//   console.log("BodySchema", BodySchema.data);

//   if (!BodySchema.success) {
//     res.status(400).json({ error: "erro  prioridades" });
//   }

//   const ParamsSchema = SenhaSchemaParams.safeParse(req.params);
//   if (!ParamsSchema.success) {
//     res.status(400).json({ error: "erro ao passar os params" });
//     return;
//   }

//   const newSenha = await senha.updateSenha({
//     ...ParamsSchema.data,
//     ...BodySchema.data,
//     senhaId: parseInt(ParamsSchema.data.senhaId),
//   });

//   if (!newSenha) {
//     res.status(500).json({ error: "Erro ao criar Senha" });
//     return;
//   }
//   res.status(201).json(newSenha);
// };
