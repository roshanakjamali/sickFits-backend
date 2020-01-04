const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomBytes } = require("crypto");
const { promisify } = require("util");
const stripe = require("../stripe");

const { hasPermission } = require("../utils");
const { transport, makeANiceEmail } = require("../mail");

const Mutations = {
  async createItem(parent, args, ctx, info) {
    // check user is logged in
    if (!ctx.request.userId) {
      throw new Error("You must be logged in to do that!");
    }
    const item = await ctx.db.mutation.createItem(
      {
        data: {
          // This is how to create a relationship between the Item and User
          user: {
            connect: {
              id: ctx.request.userId
            }
          },
          ...args
        }
      },
      info
    );
    return item;
  },
  updateItem(parent, args, ctx, info) {
    //first copy of the updates
    const updates = { ...args };
    // remove the ID
    delete updates.id;
    //run the update method
    return ctx.db.mutation.updateItem(
      {
        data: updates,
        where: {
          id: args.id
        }
      },
      info
    );
  },
  async deleteItem(parent, args, ctx, info) {
    const where = { id: args.id };
    // 1.find the item
    const item = await ctx.db.query.item({ where }, `{ id title user {id}}`);
    // 2.check if the own that item, or have the permission
    const ownsItem = ctx.request.userId === item.user.id;
    const hasPermissions = ctx.request.user.permissions.some(permission =>
      ["ADMIN", "ITEMDELETE"].includes(permission)
    );

    if (!ownsItem && !hasPermissions) {
      throw new Error("You don't have permission to do that!");
    }
    // 3.delete it
    return ctx.db.mutation.deleteItem({ where }, info);
  },
  async signup(parent, args, ctx, info) {
    // lowercase the email
    args.email = args.email.toLowerCase();
    // hash the password
    const password = await bcrypt.hash(args.password, 10);
    // create the user in database
    const user = await ctx.db.mutation.createUser(
      {
        data: {
          ...args,
          password,
          permissions: { set: ["USER"] }
        }
      },
      info
    );
    //create the JWT token for them
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // WE SET THE jwt AS COOKIE ON THE RESPONSE
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    // finally return user to browser
    return user;
  },
  async signin(parent, { email, password }, ctx, info) {
    // 1.check if there is a user with this email
    const user = await ctx.db.query.user({ where: { email } });
    if (!user) {
      throw new Error(`No such user found for email ${email}`);
    }
    // 2.check if their password is correct
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error("Invalid password");
    }
    // 3.generate the JWT Token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // 4.set the cookie with the token
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    // 5.return user to browser
    return user;
  },
  signout(parent, args, ctx, info) {
    ctx.response.clearCookie("token");
    return {
      message: "Goodbye!"
    };
  },
  async requestReset(parent, args, ctx, info) {
    // 1.check if this is real user
    const user = await ctx.db.query.user({ where: { email: args.email } });
    if (!user) {
      throw new Error(`No such user found for email ${args.email}`);
    }
    // 2.set a reset token and expiry on that user
    const randomBytesProsimified = promisify(randomBytes);
    const resetToken = (await randomBytesProsimified(20)).toString("hex");
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry }
    });
    // 3.email them that reset token
    const mailRes = await transport.sendMail({
      from: "roshanakjamali@gmail.com",
      to: user.email,
      subject: "Password Reset Token",
      html: makeANiceEmail(
        `Your Password Reset Token Is Here! \n\n <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Click Here To Reset!</a>`
      )
    });

    // 4.return the message
    return { message: "Thanks!" };
  },
  async resetPassword(parent, args, ctx, info) {
    // 1.check if the password match
    if (args.password !== args.confirmPassword) {
      throw new Error("Your Password don't Match");
    }
    // 2.check if its a legit reset token
    // 3.check if its expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000
      }
    });
    if (!user) {
      throw new Error("This token is wither invalid or expired!");
    }
    // 4.hash the new password
    const password = await bcrypt.hash(args.password, 10);
    // 5.save the new password to the user and remove old resetToken
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null
      }
    });
    // 6.generate jwt
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
    // 7.set the JWT cookie
    ctx.response.cookie("token", token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    });
    // 8.return the new user
    return updatedUser;
  },
  async updatePermissions(parent, args, ctx, info) {
    // 1.Check if they are logged in
    if (!ctx.request.userId) {
      throw new Error("You must be logged in!");
    }
    // 2.Query the current user(**logged in user)
    const user = await ctx.db.query.user(
      { where: { id: ctx.request.userId } },
      info
    );
    // 3.Check if they have permission to do this
    hasPermission(user, ["ADMIN", "PERMISSIONUPDATE"]);
    // 4.Update the permissions
    return ctx.db.mutation.updateUser(
      {
        data: {
          permissions: {
            set: args.permissions
          }
        },
        where: { id: args.userId } //** the user that has been updated
      },
      info
    );
  },
  async addToCart(parent, args, ctx, info) {
    // 1.Make sure they are signed in
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error("You must be logged in!");
    }
    // 2. Query the user's current cart
    const [existingCartItem] = await ctx.db.query.cartItems(
      {
        where: {
          user: { id: userId },
          item: { id: args.id }
        }
      },
      info
    );
    // 3. Check if that item is already in their cart and increment by 1 if ite
    if (existingCartItem) {
      return ctx.db.mutation.updateCartItem(
        {
          where: {
            id: existingCartItem.id
          },
          data: {
            quantity: existingCartItem.quantity + 1
          }
        },
        info
      );
    }
    // 4. if it is not, create a fresh cartItem for that user
    return ctx.db.mutation.createCartItem({
      data: {
        user: {
          connect: {
            id: userId
          }
        },
        item: {
          connect: {
            id: args.id
          }
        }
      }
    });
  },
  async removeFromCart(parent, args, ctx, info) {
    // 1.find the cart item
    const cartItem = await ctx.db.query.cartItem(
      {
        where: {
          id: args.id
        }
      },
      `{id, user { id }}`
    );
    // 1.5 check cart item found
    if (!cartItem) throw new Error("No CartItem found!");
    // 2.make sure they own that cart item
    const { user } = cartItem;
    if (user.id !== ctx.request.userId) {
      throw new Error("This item is not Yours!");
    }
    // 3.delete that cart item
    return ctx.db.mutation.deleteCartItem(
      {
        where: {
          id: args.id
        }
      },
      info
    );
  },
  async createOrder(parent, args, ctx, info) {
    // 1.query the current user and make sure they are signed in too
    const { userId } = ctx.request;
    if (!userId) {
      throw new Error("You must be signed in!");
    }
    const user = await ctx.db.query.user(
      {
        where: {
          id: userId
        }
      },
      `{
          id 
          name 
          email 
          cart { 
            id 
            quantity 
            item { 
              title 
              price 
              id 
              description 
              image
              largeImage
            }
          }
        }`
    );
    // 2.recalculate the total for the price
    const amount = user.cart.reduce(
      (tally, cartItem) => tally + cartItem.item.price * cartItem.quantity,
      0
    );
    // 3.Create the stripe charge(turn token into money)
    const charge = await stripe.charges.create({
      amount,
      currency: "USD",
      source: args.token
    });
    // 4.convert the cart items to order items
    const orderItems = user.cart.map(cartItem => {
      const orderItem = {
        ...cartItem.item,
        quantity: cartItem.quantity,
        user: {
          connect: {
            id: userId
          }
        }
      };
      delete orderItem.id;
      return orderItem;
    });
    // 5.create the order
    const order = await ctx.db.mutation.createOrder({
      data: {
        total: charge.amount,
        charge: charge.id,
        items: { create: orderItems },
        user: { connect: { id: userId } }
      }
    });
    // 6.clean up = clean the user cart, delete cartItems
    const cartItemsId = user.cart.map(cartItem => cartItem.id);
    await ctx.db.mutation.deleteManyCartItems({
      where: {
        id_in: cartItemsId
      }
    });
    // 7.return the order to the client
    return order;
  }
};

module.exports = Mutations;
