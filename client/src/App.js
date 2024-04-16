import 'bootstrap/dist/css/bootstrap.min.css';
import 'bootstrap/dist/js/bootstrap.js';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { Routes, Route } from 'react-router-dom';
import Home from './Components/Home';
import Header from './Components/Header';
import Login from './Components/Login';
import Dashboard from './Components/DashBoard/Dashboard';
import Error from './Components/Error';
// import Notification from './Components/pages/Notification';
import BasicInform from './Components/pages/Basic_Inform.js';
import Personal from './Components/pages/Personal_Inform.js';
import Read from './Components/pages/Profile_Table/Read';
import View from './Components/pages/Profile_Table/View';
import Decision from './Components/pages/Decision/Decision.js';
import Readd from './Components/pages/Decision/Readd.js';
import Profile from './Components/DashBoard/Profile.js';
import { useEffect } from 'react';
import axios from 'axios';

function App() {
  console.log("one is working")

  const setAuthToken = () => {
    
    const token = localStorage.getItem('token');

    if (token) {
      axios.defaults.headers.common['authorization'] = `Bearer ${token}`;
    }
  };
  setAuthToken();

  useEffect(() => {
  }, []);

  return (
    <div>
      <Header />
      <Routes>
        {/* Dashboard Routes */}
        <Route path='/' element={<Home />} />
        <Route path='/login' element={<Login />} />
        <Route path='/dashboard' element={<Dashboard />} />
        <Route path='/profile' element={<Profile />} />
        <Route path='/decision' element={<Decision />} />
        {/* <Route path='/notification' element={<Notification />} /> */}

        {/* Profile Routes */}
        <Route path='/basic' element={<BasicInform />} />
        <Route path='/personal' element={<Personal />} />
        <Route path='/read' element={<Read />} />
        <Route path='/view' element={<View />} />

        {/* Decision Routes */}
        <Route path='/decision' element={<Decision />} />
        <Route path='/decision/:id' element={<Decision />} />
        <Route path='/readd' element={<Readd />} />
        <Route path='*' element={<Error/>}/>
      </Routes>
    </div>
  );
}

export default App;
