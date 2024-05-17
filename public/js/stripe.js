import axios from 'axios';
import { showAlert } from './alerts';
const stripe = Stripe('pk_test_51PDpKw2N3DaQmn2IwPnGX9Lh8Li4bODQRXd9c5nMToDgUUkdSOqKXPGBIWJa2PlOWwBkmJQ7kt1BnxPSpJQVQ8am00Px5GmNXT');

export const bookTour = async tourId => {
    try {
        //1) Get checkout session from API
        const session = await axios(`http://127.0.0.1:3000/api/v1/bookings/checkout-session/${tourId}`);



        //2) Create checkout form + charge credit card form
        await stripe.redirectToCheckout({
            sessionId: session.data.session.id
        });
    } catch (err) {
        showAlert('error', err);
    }
};