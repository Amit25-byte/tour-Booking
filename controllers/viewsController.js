const Tour = require('../models/tourModel');
const User = require('../models/userModel');
const Booking = require('../models/bookingModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');

exports.getOverview = catchAsync(async (req, res) => {
    //1) Get tour data from collections
    const tours = await Tour.find();
    //2) Build template

    //3) Render that template using tour data from 1
    res.status(200).render('overview', {
        title: 'All Tours',
        tours
    });
});

exports.getTour = catchAsync(async (req, res, next) => {
    const tour = await Tour.findOne({ slug: req.params.slug }).populate({
        path: 'reviews',
        fields: 'review rating user'
    });

    if (!tour) {
        return next(new AppError('There is no tour with that name!', 400));
    }
    res.status(200).render('tour', {
        title: `${tour.name} Tour`,
        tour
    });
});

exports.getLoginForm = catchAsync(async (req, res, next) => {
    //1)Get user from database collections
    // const user = await User.find();

    //2)Build the template

    //3)Render that template using user data
    res.status(200).render('login', {
        title: 'Log in',
        // user
    });
});

exports.getAccount = (res, req) => {
    res.status(200).render('account', {
        title: 'Youe Account',
        // user
    });

}

exports.getMyTours = catchAsync(async (req, res, next) => {
    //1) Find all booking
    const bookings = await Booking.find({ user: req.user.id });

    //2)Find tours with the IDs
    const tourIDs = booking.map(el => el.tour);
    const tours = await Tour.find({ _id: { $in: tourIDs } });

    res.status(200).render('overview', {
        title: 'My Tours',
        tours
    });
});


exports.updateUserData = catchAsync(async (req, res, next) => {
    const updatedUser = await User.findByIdAndUpdate(
        req.user.id,
        {
            name: req.body.name,
            email: rea.body.email
        },
        {
            new: true,
            runValidators: true
        }
    );
    res.status(200).render('account', {
        title: 'Youe Account',
        user: updatedUser
    });
});