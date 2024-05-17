const AppError = require("../utils/appError");

const hadleJWTError = () => new AppError('Invalid token. please log in again', 401);
const handleJWTExpiredError = () => new AppError('Your time has expired, please log in again', 401);

const handleCastErrorDB = err => {
    const message = `Invalid ${err.path}:${err.value}.`;
    return new AppError(message, 400);
};

const handleDuplicateFieldsDB = err => {
    const value = err.errmsg.match(/(["'])(\\?.)*?\1/)[0];
    const message = `Duplicate field value:${value} please use another name`;
    console.log(value);
    return new AppError(message, 400);
}
const handleValidationFieldsDB = err => {
    const errors = Object.values(err.errors).map(el => el.message);
    const message = `Invalid input data.${errors.join('. ')}`;
    return new AppError(message, 400);
};
const sendErrorDev = (err, req, res) => {
    if (req.originalUrl.startsWith('/api')) {
        return res.status(err.statusCode).json({
            status: err.status,
            error: err,
            message: err.message,
            stack: err.stack
        });
    }
    return res.status(err.statusCode).render('error', {
        title: ' Something went wrong',
        msg: err.message
    });
};
const sendErrorProd = (err, req, res) => {
    //API
    if (req.originalUrl.startsWith('/api')) {
        //A)Operational,trusted error: send message to client 
        if (err.isOperational) {

            return res.status(err.statusCode).json({
                status: err.status,
                message: err.message
            });
        }
        //B) Programming or other unknown error:don't take error deyails
        //1)log to the console
        console.log("ERROR", err);

        //2)Send generic message
        res.status(500).json({
            status: 'error',
            message: 'Something went wrong'
        });
    }
    //B)Rendered Websites
    if (err.isOperational) {

        return res.status(err.statusCode).render('error', {
            title: ' Something went wrong',
            msg: err.message
        });
    }
    //1)log to the console
    console.log("ERROR", err);

    //2)Send generic message
    return res.status(err.statusCode).render('error', {
        title: ' Something went wrong',
        msg: 'Please try again later!'
    });
};
module.exports = (err, req, res, next) => {
    err.statusCode = err.statusCode || 500,
        err.status = err.status || 'error';


    if (process.env.NODE_ENV === 'development') {
        sendErrorDev(err, req, res)

    } else if (process.env.NODE_ENV === 'production') {
        let error = { ...err };
        error.message = err.message;
        if (error.name === 'CastError') error = handleCastErrorDB(error);
        if (error.code === 11000) error = handleDuplicateFieldsDB(error);
        if (error.name === 'ValidationError') error = handleValidationFieldsDB(error);
        if (error.name === 'JsonWebTokenError') error = hadleJWTError();
        if (error.name === 'TokenExpiredError') error = handleJWTExpiredError();
        sendErrorProd(error, req, res);
    };
};
