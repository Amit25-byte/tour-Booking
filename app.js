const path = require('path');
const express = require('express');
const morgan = require('morgan');
const globalErrorHandler = require('./controllers/errorController')
const tourRouter = require('./routes/tourRoutes');
const userRouter = require('./routes/userRoutes');
const reviewRouter = require('./routes/reviewRoutes');
const bookingRouter = require('./routes/bookingRoutes');
const viewRouter = require('./routes/viewRoutes');
const cookieParser = require('cookie-parser');

const AppError = require('./utils/appError');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const app = express();

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

const helmet = require('helmet');
// 1) Global Middleware

// Serving static files
app.use(express.static(path.join(__dirname, 'public')));

// set security HTTP header
app.use(helmet());

// Development logging
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}
// Limit requests from same APIs
const limiter = rateLimit({
    max: 100,
    windowMs: 60 * 60 * 1000,
    message: 'Too many requests from this IP.please try again in an hour'
});
app.use('/api', limiter);
// Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// Data sanitization against NoSQL query injection
app.use(mongoSanitize());
//Data sanitization against xss
app.use(xss());

//prevent parameter sollutions
app.use(hpp({
    whitelist: [
        'duration',
        'ratingsAverage',
        'ratingQuantity',
        'maxGroupSize',
        'difficulty',
        'price'
    ]
}));



app.use((req, res, next) => {
    console.log('Hello from the middleware');
    next();
});

app.use((req, res, next) => {
    req.requestTime = new Date().toISOString();
    // console.log(req.headers);
    next();
});



//3)Routes
app.use('/', viewRouter);
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);
app.use('/api/v1/reviews', reviewRouter);
app.use('/api/v1/booking', bookingRouter);


app.all('*', (req, res, next) => {
    next(new AppError(`Can't find ${req.originalUrl} on this server`, 404));

});

app.use(globalErrorHandler);

module.exports = app;
