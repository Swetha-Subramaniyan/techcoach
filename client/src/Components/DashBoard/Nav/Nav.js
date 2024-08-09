import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { Card, Typography, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Grid, Box, CircularProgress, Button } from '@mui/material';
import { AssignmentTurnedIn, HourglassEmpty, Share } from '@mui/icons-material';
import ModelTrainingIcon from '@mui/icons-material/ModelTraining';
import './Nav.css';
import withAuth from '../../withAuth';
import { getSharedDecisionDetails } from '../../Group/Network_Call';

const Nav = () => {
  const navigate = useNavigate();
  const [data, setData] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [showPendingDecisions, setShowPendingDecisions] = useState(false);
  const [pendingDecisionsData, setPendingDecisionsData] = useState([]);
  const [receivedDecisionsCount, setReceivedDecisionsCount] = useState(0);
  const [loading, setLoading] = useState(true);
  let loggedInUserId;

  const [sharedDecisionDetails, setSharedDecisionDetails] = useState(null);

  useEffect(() => {
    const fetchSharedDecisionsDetails = async () => {
      try {
        const details = await getSharedDecisionDetails();

        setSharedDecisionDetails(details);
        setLoading(false);
      } catch (error) {
        console.error("Failed to fetch inner circle details", error);
        setLoading(false);
      }
    };
    fetchSharedDecisionsDetails();
  }, []);

  const sharedDecisionCount = Array.isArray(sharedDecisionDetails?.sharedDecisions) ? sharedDecisionDetails.sharedDecisions.length : 0;
  // console.log("shhhhhhhhhhhh", sharedDecisionCount);

  useEffect(() => {
    const loadData = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get(`${process.env.REACT_APP_API_URL}/api/`, {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        const responseData = response.data;
        if (Array.isArray(responseData.decisionData)) {
          setData(responseData.decisionData);
        } else {
          console.error("Invalid response format:", responseData);
        }
      } catch (error) {
        console.error("Error fetching data:", error.message);
      }
    };

    loadData();
  }, []);

  useEffect(() => {
    const pendingDecisions = data.filter(decision => {
      return decision.user_id === loggedInUserId && !decision.decision_taken_date;
    });
    console.log("pending decisions", pendingDecisions);
    setPendingDecisionsData(pendingDecisions);
  }, [data, loggedInUserId]);

  useEffect(() => {
    const sharedDecisionCount = async () => {
      try {
        const token = localStorage.getItem('token');
        const response = await axios.get(`${process.env.REACT_APP_API_URL}/group/getSharedDecisions`, {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        const sharedDecisions = response.data.decisionCount;
        // console.log("countttt", sharedDecisions);

        setReceivedDecisionsCount(sharedDecisions);
        setLoading(false);
      } catch (error) {
        console.error("Error fetching data:", error.message);
        setLoading(false);
      }
    };

    sharedDecisionCount();
  }, []);

  // const filteredData = data.filter(decision => {
  //   return (
  //     decision.user_id === loggedInUserId &&
  //     ((decision.decision_name && decision.decision_name.toLowerCase().includes(searchTerm.toLowerCase())) ||
  //       (decision.tagsArray && decision.tagsArray.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))) ||
  //       (!decision.decision_taken_date))
  //   );
  // });

  const filteredData = data.filter(decision => {
    const decisionNameMatch = decision.decision_name && decision.decision_name.toLowerCase().includes(searchTerm.toLowerCase());
    const tagMatch = Array.isArray(decision.tags) && decision.tags.some(tag => 
      tag.tag_name && tag.tag_name.toLowerCase().includes(searchTerm.toLowerCase())
    );
    const isPending = !decision.decision_taken_date;
    return decision.user_id === loggedInUserId && (decisionNameMatch || tagMatch || isPending);
  });

  
  const liveDecisionsCount = filteredData.length;
  const pendingDecisionsCount = pendingDecisionsData.length;

  const togglePendingDecisions = () => {
    setShowPendingDecisions(!showPendingDecisions);
  };

  const navigateToSharedDecisions = () => {
    navigate('/sharedDecisions');
  };

  const navigateToReceivedDecisions = () => {
    navigate('/sharedByMe');
  };

  const navigateToTotalDecisions = () => {
    navigate('/readd');
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <div style={{ maxWidth: "95%", display: "flex", flexDirection: "column", gap: "1rem", margin: "3rem" }}>
      <Grid container spacing={4}>
        <Grid item xs={12} sm={6} md={3}>
          <CustomCard
            icon={<AssignmentTurnedIn />}
            title="Total Decisions"
            count={liveDecisionsCount}
            onClick={navigateToTotalDecisions}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <CustomCard
            icon={<HourglassEmpty />}
            title="Pending Decisions"
            count={pendingDecisionsCount}
            onClick={togglePendingDecisions}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <CustomCard
            icon={<ModelTrainingIcon />}
            title="Shared with me"
            count={receivedDecisionsCount}
            onClick={navigateToSharedDecisions}
          />
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <CustomCard
            icon={<Share />}
            title="Shared by me"
            count={sharedDecisionCount}
            onClick={navigateToReceivedDecisions}
          />
        </Grid>
      </Grid>
      <Grid container spacing={4}>
        <Grid item xs={12}>
          {showPendingDecisions && (
            <div>
              <Typography variant="h6" style={{ marginBottom: "1rem" }}>Pending Decisions</Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ backgroundColor: '#526D82', color: '#ffffff', border: '1px solid #ffffff' }}>
                        <Typography variant="h6">Decision Name</Typography>
                      </TableCell>
                      <TableCell sx={{ backgroundColor: '#526D82', color: '#ffffff', border: '1px solid #ffffff' }}>
                        <Typography variant="h6">Decision Due Date</Typography>
                      </TableCell>
                      <TableCell sx={{ backgroundColor: '#526D82', color: '#ffffff', border: '1px solid #ffffff' }}>
                        <Typography variant="h6">Decision Details</Typography>
                      </TableCell>
                      <TableCell sx={{ backgroundColor: '#526D82', color: '#ffffff', border: '1px solid #ffffff' }}>
                        <Typography variant="h6">Action</Typography>
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {pendingDecisionsData.map((decision, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ border: '1px solid #526D82' }}>{decision.decision_name}</TableCell>
                        <TableCell sx={{ border: '1px solid #526D82' }}>{new Date(decision.decision_due_date).toLocaleDateString()}</TableCell>
                        <TableCell sx={{ border: '1px solid #526D82' }}>{decision.user_statement}</TableCell>
                        <TableCell sx={{ border: '1px solid #526D82' }}>
                          <Button
                            onClick={() => navigate(`/decision/${decision.decision_id}`)}
                            sx={{
                              backgroundColor: '#1976d2',
                              color: '#fff',
                              '&:hover': {
                                backgroundColor: '#1565c0',
                              },
                              padding: '6px 12px',
                              fontSize: '14px',
                              borderRadius: '4px',
                            }}
                          >
                            Edit
                          </Button>                 
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </div>
          )}
        </Grid>
      </Grid>
    </div>
  );
};

const CustomCard = ({ icon, title, count, onClick }) => {
  const [hovered, setHovered] = useState(false);

  const handleMouseEnter = () => {
    setHovered(true);
  };

  const handleMouseLeave = () => {
    setHovered(false);
  };

  const cardStyle = {
    marginBottom: 12,
    border: '1px solid #526D82',
    borderRadius: '8px',
    backgroundColor: hovered ? '#d7ebfc' : '#ffffff',
    width: '100%',
    height: '100%',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '15px',
    cursor: 'pointer',
    transition: 'all 0.3s ease-in-out'
  };

  return (
    <Card
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onClick={onClick}
      style={cardStyle}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: "0.5rem" }}>
        {icon}
        <Typography variant="h5">{title}</Typography>
      </Box>
      <Box>
        <Typography variant="h4">{count}</Typography>
      </Box>
    </Card>
  );
};

export default withAuth(Nav);
