import { SecurePassword } from "@blitzjs/auth"
import { resolver } from "@blitzjs/rpc"
import db from "db"
import { Role } from "types"
import { Signup } from "../validations"

export default resolver.pipe(resolver.zod(Signup), async ({ email, password }, ctx) => {
  // 1. Get the user
  const checkIfUserExists = await db.user.findFirst({ where: { email: email.toLowerCase() } })
  if (checkIfUserExists) {
    throw new Error(
      "This e-mail is already associated with another account in our database. Please use another e-mail to sign up."
    )
  }

  const hashedPassword = await SecurePassword.hash(password.trim())
  const user = await db.user.create({
    data: { email: email.toLowerCase().trim(), hashedPassword, role: "USER" },
    select: { id: true, name: true, email: true, role: true },
  })

  await ctx.session.$create({ userId: user.id, role: user.role as Role })
  return user
})
